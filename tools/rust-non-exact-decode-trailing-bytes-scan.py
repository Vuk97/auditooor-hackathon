#!/usr/bin/env python3
"""Rust non-exact EIP-2718 decode trailing-bytes scanner — Wave H-3B.

Detects use of ``decode_2718(`` (non-exact form) without a subsequent
``is_empty()`` guard on the buffer remainder, or where ``decode_2718_exact``
is available but not used.

Bug shape (patch 6a1333dd): attributes consolidation path called
``BaseTxEnvelope::decode_2718(&mut &attr_tx_bytes[..])`` which does NOT reject
trailing bytes. A sequencer payload carrying ``<valid tx bytes> + <garbage>``
would be accepted, potentially causing EL/CL state divergence when the same
bytes are decoded in an alternate context.  The fix uses ``decode_2718_exact``.

Pattern IDs
-----------
* ``decode_2718_without_exact``  — bare ``decode_2718(`` call in a non-test fn.

Note: the scanner flags ALL ``decode_2718`` call sites. Sites that also call
``decode_2718_exact`` in the same function body are tagged
``confidence="low"`` (may already use exact path elsewhere).  Sites with
no ``is_empty`` guard are tagged ``confidence="high"``.

CLI: ``--workspace``, ``--strict``, ``--print-json``.
``--strict`` exits 1 when any row is emitted.

Examples
--------

::

    python3 tools/rust-non-exact-decode-trailing-bytes-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-non-exact-decode-trailing-bytes-scan.py \\
        --workspace ~/audits/base-azul --strict
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.rust_non_exact_decode_trailing_bytes_scan.v1"

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

# Foot-gun #3: \b not ^
DECODE_2718_RE = re.compile(r"\bdecode_2718\s*\(")
DECODE_2718_EXACT_RE = re.compile(r"\bdecode_2718_exact\s*\(")
IS_EMPTY_GUARD_RE = re.compile(r"\bis_empty\s*\(\s*\)")

FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)

INPUT_SOURCE_BY_PATH = (
    ("/gossip/", "gossip"),
    ("/p2p/", "p2p"),
    ("/network/", "p2p"),
    ("/rpc-types-engine/", "engine_api"),
    ("/engine/", "engine_api"),
    ("/rpc/", "rpc"),
    ("/blob", "blob"),
    ("/consensus/protocol/", "untrusted_l1"),
    ("/consensus/derive/", "untrusted_l1"),
    ("/batcher/", "untrusted_l1"),
    ("/batch/", "untrusted_l1"),
    ("/tee/", "tee_attestation"),
    ("/proof/", "untrusted_proof"),
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class DecodeRow:
    file: str
    line: int
    pattern_id: str
    containing_fn: str
    input_source: str
    has_is_empty_guard: bool
    has_exact_in_same_fn: bool
    snippet: str
    confidence: str
    candidate_status: str = "kill_or_reframe"


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
    for tok, src in INPUT_SOURCE_BY_PATH:
        if tok in "/" + rel_path:
            return src
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


def _enclosing_function_body(text: str, offset: int) -> str:
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


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[DecodeRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)
    rows: list[DecodeRow] = []

    for m in DECODE_2718_RE.finditer(cleaned):
        line = _line_for_offset(cleaned, m.start())
        fn_name = _enclosing_function(cleaned, m.start())
        body = _enclosing_function_body(cleaned, m.start())
        has_empty_guard = bool(IS_EMPTY_GUARD_RE.search(body))
        has_exact = bool(DECODE_2718_EXACT_RE.search(body))
        # Confidence: high if no guard and no exact alternative in same fn.
        if has_exact:
            confidence = "low"
        elif has_empty_guard:
            confidence = "medium"
        else:
            confidence = "high"
        rows.append(
            DecodeRow(
                file=rel,
                line=line,
                pattern_id="decode_2718_without_exact",
                containing_fn=fn_name,
                input_source=src,
                has_is_empty_guard=has_empty_guard,
                has_exact_in_same_fn=has_exact,
                snippet=_snippet(cleaned, m.start()),
                confidence=confidence,
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


def _count_by(rows: list[DecodeRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[DecodeRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[DecodeRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-non-exact-decode-trailing-bytes-scan.py",
        description=(
            "Wave H-3B — EIP-2718 non-exact decode trailing-bytes scanner. "
            "Finds decode_2718() calls that accept trailing bytes. "
            "Bug shape: patch 6a1333dd."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--scan-root",
        action="append",
        default=[],
        dest="scan_roots",
    )
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--out-json", default="")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when at least one row is emitted.",
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[rust-non-exact-decode-trailing-bytes-scan] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.scan_roots))

    print_json = args.print_json or args.out_json == "-"
    if print_json:
        sys.stdout.write(
            json.dumps(
                {
                    "schema": SCHEMA_VERSION,
                    "rows": [asdict(r) for r in rows],
                    "pattern_counts": _count_by(rows, lambda r: r.pattern_id),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    else:
        print(
            f"[rust-non-exact-decode-trailing-bytes-scan] {len(rows)} row(s)",
            file=sys.stderr,
        )

    if args.strict and rows:
        print(
            f"[rust-non-exact-decode-trailing-bytes-scan] STRICT FAIL: {len(rows)} row(s)",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
