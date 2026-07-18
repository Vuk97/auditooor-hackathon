#!/usr/bin/env python3
"""Rust host-controlled length cast → unbounded allocation scanner — Wave H-3F.

Wave 6 Worker F promoted two Swival-derived Medium candidates that share this
call-site shape:

  1. ``external/base/crates/proof/preimage/src/oracle.rs:33-55``
     OracleReader::write_key reads an 8-byte (u64) length from the host, casts
     it to usize, and OracleReader::get allocates ``vec![0; length]`` without an
     upper-bound cap.  A malicious or buggy host can cause an unbounded heap
     allocation every time the client requests a preimage.
     (Swival swival-rust-stdlib-192)

  2. ``external/base/crates/proof/preimage/src/hint.rs:78-95``
     HintReader::next_hint reads a u32 from the hint channel, casts it to usize,
     and allocates ``vec![0u8; len as usize]`` without a cap.  A malicious peer
     on the hint channel can request up to 4 GiB per call.
     (Swival swival-rust-stdlib-196)

Distinguishing feature vs ``rust-decode-bomb-scan`` (existing):
- ``rust-decode-bomb-scan`` catches ``Vec::with_capacity(<attacker_len_token>)``
  and ``vec![<val>; <attacker_len_token>]`` where the length IS an
  attacker-named token detected by heuristic label.
- THIS scanner catches the PREIMAGE-ORACLE / CHANNEL-READ call-site shape:
  a ``read_exact``/``read_<word>``/``from_be_bytes`` length read from a
  host-/oracle-/channel-/hint-prefixed channel, followed by a ``vec![..; <var>
  as usize]`` or ``Vec::with_capacity(<var> as usize)`` within ≤10 lines.
  The distinguishing pattern is the explicit ``as usize`` cast from an integer
  type (u32/u64) whose value comes from a host-controlled channel.

Pattern IDs
-----------
* ``host_u64_to_usize_vec_alloc``   — u64 from host channel → vec/capacity as usize
* ``host_u32_to_usize_vec_alloc``   — u32 from host channel → vec/capacity as usize
* ``channel_read_then_vec_alloc``   — generic read_exact into length buffer → vec alloc

Confidence levels
-----------------
* ``high``   — read is from a host/oracle/hint/channel-prefixed source AND
               ``as usize`` cast feeds a ``vec!`` macro or ``Vec::with_capacity``
               within ≤5 lines, with no length-cap guard found.
* ``medium`` — read is detected but cap regex matches (may be suppressed).
* ``low``    — heuristic match only (>5 lines between read and alloc).

Default-to-kill discipline: every row carries ``candidate_status``.
``STRICT=1`` / ``--strict`` exits 1 when any row is emitted.

CLI: ``--workspace``, ``--strict``, ``--print-json``.

Examples
--------

::

    python3 tools/rust-host-length-cast-unbounded-alloc-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-host-length-cast-unbounded-alloc-scan.py \\
        --workspace ~/audits/base-azul --strict
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.rust_host_length_cast_unbounded_alloc_scan.v1"

DEFAULT_SCAN_ROOTS = (
    "external/base/crates",
    "crates",
)

TEST_PATH_TOKENS = (
    "/tests/",
    "/test_",
    "/testing/",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
)

# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

# Foot-gun #3: \b not ^.

# Host/oracle/channel source indicators in file paths.
HOST_SOURCE_PATH_TOKENS = (
    "/preimage/",
    "/oracle",
    "/hint",
    "/proof/",
    "/host/",
    "/client/",
    "/fpvm",
    "/channel",
)

# Length read patterns: read_exact into a fixed-size buffer followed by
# from_be_bytes, or direct read_<word>/read_u32/read_u64.
#
# Pattern A: let mut len_buf = [0u8; N]; channel.read_exact(&mut len_buf)...;
#            let len = u32::from_be_bytes(len_buf);
LENGTH_BUF_RE = re.compile(
    r"\blet\s+(?:mut\s+)?([a-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:u(?:32|64)|usize)\s*::\s*from_(?:be|le)_bytes\s*\(",
)

# Pattern B: channel.read_u32() / oracle.read_word() / host.read_u64() etc.
READ_WORD_RE = re.compile(
    r"\blet\s+(?:mut\s+)?([a-z_][A-Za-z0-9_]*)\s*"
    r"(?::\s*u(?:32|64|128|size))?\s*=\s*"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"\s*\.\s*read_(?:u32|u64|u128|word|length|exact)\s*\(",
)

# Host-channel patterns in variable or field names (for scope narrowing).
HOST_CHANNEL_TOKENS = (
    "channel",
    "oracle",
    "hint",
    "host",
    "preimage",
    "client",
    "stream",
    "reader",
    "conn",
    "socket",
)

# Allocation that uses a variable cast as usize.
# Matches: vec![0; len as usize]  OR  Vec::with_capacity(len as usize)
#          OR vec![0u8; len as usize]  OR  vec![0; (len) as usize]
USIZE_ALLOC_RE = re.compile(
    r"\b(?:vec!\s*\[\s*[^;\]]+;\s*|Vec\s*::\s*with_capacity\s*\(\s*)"
    r"([a-z_][A-Za-z0-9_]*)\s+as\s+usize",
)

# try_into().unwrap() cast shape: len.try_into().unwrap() or
# usize::try_from(len).unwrap()
TRY_INTO_USIZE_RE = re.compile(
    r"\b([a-z_][A-Za-z0-9_]*)\s*\.\s*try_into\s*\(\s*\)\s*"
    r"(?:\s*\.\s*map_err[^;]*)?\s*\.\s*(?:unwrap|expect)\s*\(",
)

# Length-cap evidence: guard before allocation.
LEN_CAP_TOKENS = (
    "MAX_",
    "_MAX",
    "MAXIMUM_",
    "max_preimage",
    "max_length",
    "max_size",
    "max_hint",
    "saturating_min",
    ".min(",
    "ensure!",
    "bail!",
    "if len >",
    "if length >",
    "if size >",
)

# Function declaration boundary for enclosing-function heuristics.
FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class AllocRow:
    file: str
    line: int
    pattern_id: str
    function: str
    length_variable: str
    length_type: str
    attacker_input_source: str
    length_cap_present: bool
    length_cap_indicator: str
    confidence: str
    snippet: str
    recommendation: str = (
        "Add an upper-bound cap (e.g. if length > MAX_PREIMAGE_SIZE { return Err(...) }) "
        "before allocating the Vec."
    )
    candidate_status: str = "kill_or_reframe"
    submission_posture: str = "NOT_SUBMIT_READY"
    evidence_class: str = "detector_hit"
    harness_task: str = (
        "Fuzz: drive a Mock Channel that returns a large u32/u64 length to the "
        "reader function; assert the process does not OOM and rejects lengths "
        "above a sane cap (e.g. 16 MiB)."
    )
    kill_or_reframe_rule: str = (
        "kill_or_reframe unless a follow-up proof demonstrates that the host "
        "input source is reachable under a realistic non-bruteforce adversary "
        "scenario and measures >=30% node resource consumption."
    )
    not_applicable_impacts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_rel(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _input_source(rel_path: str) -> str:
    for tok in HOST_SOURCE_PATH_TOKENS:
        if tok in "/" + rel_path:
            return "untrusted_proof"
    return "unknown"


def _strip_test_blocks(text: str) -> str:
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*mod\s+\w+\s*\{", text[i:])
        if not m:
            out_parts.append(text[i:])
            break
        out_parts.append(text[i : i + m.start()])
        depth = 0
        j = i + m.end() - 1
        n = len(text)
        while j < n:
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out_parts)


def _enclosing_function(text: str, offset: int) -> str:
    last = "<module>"
    for m in FN_START_RE.finditer(text, 0, offset):
        last = m.group(1)
    return last


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


def _cap_present(fn_body: str, length_var: str) -> tuple[bool, str]:
    """Check if a cap guard exists for length_var in fn_body."""
    for tok in LEN_CAP_TOKENS:
        if tok in fn_body:
            # Verify the cap co-occurs with the length variable nearby.
            idx = fn_body.find(tok)
            nearby = fn_body[max(0, idx - 120) : idx + 120]
            if length_var in nearby or tok.startswith("if ") or tok.startswith("ensure"):
                return True, tok
    # Regex: if <length_var> > <cap>
    m = re.search(
        rf"if\s+{re.escape(length_var)}\s*>",
        fn_body,
    )
    if m:
        return True, "if-guard"
    return False, ""


def _is_host_channel_context(text_window: str, var: str) -> bool:
    """Heuristic: does the surrounding code show host/channel/oracle access?"""
    # Check surrounding 400 chars for host-channel keywords.
    for tok in HOST_CHANNEL_TOKENS:
        if re.search(rf"\b{re.escape(tok)}\b", text_window, re.IGNORECASE):
            return True
    return False


def _enclosing_fn_body(text: str, offset: int) -> str:
    fn_starts = [m.start() for m in FN_START_RE.finditer(text, 0, offset)]
    if not fn_starts:
        return text
    fn_start = fn_starts[-1]
    n = len(text)
    i = fn_start
    depth = 0
    body_start = -1
    while i < n:
        c = text[i]
        if c == ";" and depth == 0 and body_start == -1:
            return text[fn_start:i]
        if c == "{":
            if body_start == -1:
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and body_start != -1:
                return text[body_start : i + 1]
        i += 1
    return text[fn_start:]


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[AllocRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)
    rows: list[AllocRow] = []
    seen_lines: set[int] = set()

    # Strategy A: from_be_bytes / from_le_bytes length extraction.
    for m in LENGTH_BUF_RE.finditer(cleaned):
        var = m.group(1)
        read_end = m.end()
        # Determine type from the from_be_bytes call.
        call_text = cleaned[m.start() : m.start() + 80]
        if "u64" in call_text:
            length_type = "u64"
            pattern_id = "host_u64_to_usize_vec_alloc"
        elif "u32" in call_text:
            length_type = "u32"
            pattern_id = "host_u32_to_usize_vec_alloc"
        else:
            length_type = "usize"
            pattern_id = "channel_read_then_vec_alloc"

        # Look forward up to 600 chars for an as-usize alloc using var.
        window = cleaned[read_end : read_end + 600]
        alloc_match = re.search(
            r"\b(?:vec!\s*\[\s*[^;\]]+;\s*|Vec\s*::\s*with_capacity\s*\(\s*)"
            + re.escape(var)
            + r"\s+as\s+usize",
            window,
        )
        if not alloc_match:
            # Also check try_into shape.
            alloc_match = re.search(
                re.escape(var) + r"\s*\.\s*try_into\s*\(\s*\)\s*",
                window,
            )
        if not alloc_match:
            continue

        line = _line_for_offset(cleaned, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)

        fn_name = _enclosing_function(cleaned, m.start())
        fn_body = _enclosing_fn_body(cleaned, m.start())
        cap, cap_val = _cap_present(fn_body, var)

        # Determine confidence.
        lines_between = window[: alloc_match.start()].count("\n")
        context_window = cleaned[max(0, m.start() - 200) : read_end + 100]
        is_host = _is_host_channel_context(context_window, var) or src != "unknown"

        if is_host and not cap and lines_between <= 5:
            confidence = "high"
        elif cap:
            confidence = "medium"
        else:
            confidence = "low"

        rows.append(
            AllocRow(
                file=rel,
                line=line,
                pattern_id=pattern_id,
                function=fn_name,
                length_variable=var,
                length_type=length_type,
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_indicator=cap_val,
                confidence=confidence,
                snippet=_snippet(cleaned, m.start()),
            )
        )

    # Strategy B: direct read_u32/read_u64/read_word calls.
    for m in READ_WORD_RE.finditer(cleaned):
        var = m.group(1)
        read_end = m.end()

        # Narrow to host/channel context.
        context_window = cleaned[max(0, m.start() - 300) : m.end() + 50]
        if not _is_host_channel_context(context_window, var):
            continue

        # Determine type from declaration.
        decl_text = cleaned[m.start() : m.start() + 120]
        if "u64" in decl_text:
            length_type = "u64"
            pattern_id = "host_u64_to_usize_vec_alloc"
        elif "u32" in decl_text:
            length_type = "u32"
            pattern_id = "host_u32_to_usize_vec_alloc"
        else:
            length_type = "u32"
            pattern_id = "channel_read_then_vec_alloc"

        # Look forward for as-usize alloc.
        window = cleaned[read_end : read_end + 600]
        alloc_match = re.search(
            r"\b(?:vec!\s*\[\s*[^;\]]+;\s*|Vec\s*::\s*with_capacity\s*\(\s*)"
            + re.escape(var)
            + r"\s+as\s+usize",
            window,
        )
        if not alloc_match:
            continue

        line = _line_for_offset(cleaned, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)

        fn_name = _enclosing_function(cleaned, m.start())
        fn_body = _enclosing_fn_body(cleaned, m.start())
        cap, cap_val = _cap_present(fn_body, var)

        lines_between = window[: alloc_match.start()].count("\n")
        if not cap and lines_between <= 5:
            confidence = "high"
        elif cap:
            confidence = "medium"
        else:
            confidence = "low"

        rows.append(
            AllocRow(
                file=rel,
                line=line,
                pattern_id=pattern_id,
                function=fn_name,
                length_variable=var,
                length_type=length_type,
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_indicator=cap_val,
                confidence=confidence,
                snippet=_snippet(cleaned, m.start()),
            )
        )

    # Strategy C: direct in-line vec![0; <expr> as usize] where <expr>
    # comes from a read_exact length-buffer read in the same fn body.
    for m in USIZE_ALLOC_RE.finditer(cleaned):
        var = m.group(1)
        line = _line_for_offset(cleaned, m.start())
        if line in seen_lines:
            continue

        fn_body = _enclosing_fn_body(cleaned, m.start())
        # Only flag if there's a read_exact + from_be_bytes in the fn body.
        if not (
            re.search(r"\bread_exact\b", fn_body)
            and re.search(r"\bfrom_(?:be|le)_bytes\b", fn_body)
        ):
            continue

        if not _is_host_channel_context(fn_body[:400], var):
            continue

        seen_lines.add(line)
        fn_name = _enclosing_function(cleaned, m.start())
        cap, cap_val = _cap_present(fn_body, var)

        rows.append(
            AllocRow(
                file=rel,
                line=line,
                pattern_id="channel_read_then_vec_alloc",
                function=fn_name,
                length_variable=var,
                length_type="inferred",
                attacker_input_source=_input_source(rel),
                length_cap_present=cap,
                length_cap_indicator=cap_val,
                confidence="high" if not cap else "medium",
                snippet=_snippet(cleaned, m.start()),
            )
        )

    # Strategy D: alloc::vec![0; <var>]  (no explicit `as usize` cast) where
    # <var> is a usize returned from a host/oracle helper function.
    # Oracle shape: `let length = self.write_key(key).await?;`
    #               `let mut data_buffer = alloc::vec![0; length];`
    # The length here is already a usize (cast happened inside write_key).
    ORACLE_VEC_RE = re.compile(
        r"\b(?:alloc\s*::\s*)?vec!\s*\[\s*([^;\]]+)\s*;\s*"
        r"([a-z_][A-Za-z0-9_]*)\s*\]",
    )
    ORACLE_LEN_CALLER_RE = re.compile(
        r"\blet\s+(?:mut\s+)?([a-z_][A-Za-z0-9_]*)\s*=\s*"
        r"[A-Za-z_][A-Za-z0-9_]*"
        r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
        r"\s*\.\s*(?:write_key|read_length|get_length|fetch_length|"
        r"preimage_length|oracle_len|read_usize)\s*\(",
    )

    # For each vec without explicit as-usize cast, check if the var was assigned
    # from a host-oracle function call in the same fn body.
    for m in ORACLE_VEC_RE.finditer(cleaned):
        var = m.group(2)
        line = _line_for_offset(cleaned, m.start())
        if line in seen_lines:
            continue

        fn_body = _enclosing_fn_body(cleaned, m.start())
        # The fn body must contain a write_key / oracle call that returns the var.
        oracle_call = ORACLE_LEN_CALLER_RE.search(fn_body)
        if not oracle_call or oracle_call.group(1) != var:
            continue

        # Must be a host/oracle/channel context.
        if not _is_host_channel_context(fn_body[:500], var):
            continue

        seen_lines.add(line)
        fn_name = _enclosing_function(cleaned, m.start())
        cap, cap_val = _cap_present(fn_body, var)

        rows.append(
            AllocRow(
                file=rel,
                line=line,
                pattern_id="host_u64_to_usize_vec_alloc",
                function=fn_name,
                length_variable=var,
                length_type="usize (from oracle/host helper)",
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_indicator=cap_val,
                confidence="high" if not cap else "medium",
                snippet=_snippet(cleaned, m.start()),
            )
        )

    return rows


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------


def enumerate_files(workspace: Path, extra_roots: list[str]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    roots = rust_crate_scan_roots(workspace, DEFAULT_SCAN_ROOTS) + list(extra_roots)
    for rel in roots:
        root = (workspace / rel).resolve()
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            spath = str(path)
            if any(tok in spath for tok in TEST_PATH_TOKENS):
                continue
            if path.name.endswith("_test.rs") or path.name.endswith("_tests.rs"):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _count_by(rows: list[AllocRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[AllocRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[AllocRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-host-length-cast-unbounded-alloc-scan.py",
        description=(
            "Wave H-3F — host-controlled length cast → unbounded Vec alloc scanner. "
            "Catches preimage-oracle / channel-read shapes where a u32/u64 length "
            "from a host-controlled channel is cast to usize and used as a Vec "
            "allocation size without a cap."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Extra workspace-relative path to walk. May be passed multiple times.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON payload to stdout instead of writing files.",
    )
    parser.add_argument(
        "--out-json",
        default="",
        help="Set to '-' to print JSON to stdout (alias for --print-json).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit 1 when at least one row is emitted "
            "(STRICT=1 gate for CI)."
        ),
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[rust-host-length-cast-unbounded-alloc-scan] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.root))
    print_json = args.print_json or args.out_json == "-"

    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "row_count": len(rows),
        "pattern_counts": _count_by(rows, lambda r: r.pattern_id),
        "rows": [asdict(r) for r in rows],
    }

    if print_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        out_dir = workspace / "critical_hunt" / "host_length_alloc"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "rust_host_length_cast_unbounded_alloc_scan.json"
        json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"[rust-host-length-cast-unbounded-alloc-scan] wrote {json_path.relative_to(workspace)}",
            file=sys.stderr,
        )
        if rows:
            counts_str = ", ".join(
                f"{k}={v}"
                for k, v in sorted(_count_by(rows, lambda r: r.pattern_id).items())
            )
            print(
                f"[rust-host-length-cast-unbounded-alloc-scan] {len(rows)} rows: {counts_str}",
                file=sys.stderr,
            )
        else:
            print(
                "[rust-host-length-cast-unbounded-alloc-scan] no rows emitted",
                file=sys.stderr,
            )

    if args.strict and rows:
        print(
            f"[rust-host-length-cast-unbounded-alloc-scan] STRICT FAIL: {len(rows)} row(s) emitted",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
