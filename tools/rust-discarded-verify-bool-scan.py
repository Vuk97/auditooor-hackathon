#!/usr/bin/env python3
"""Rust discarded-verify-bool scanner — Wave H-3B.

Detects call sites where a function returning ``Result<bool, E>`` is used with
the ``?`` operator but the ``bool`` inside ``Ok(bool)`` is discarded — i.e.,
``Ok(false)`` (verification failure) is silently treated as success.

Bug shape (patch a974aa35):
``KzgProof::verify_kzg_proof(...).map_err(|_| ...)?;``
The function returns ``Result<bool, _>``.  The ``?`` propagates ``Err`` but
drops the ``bool`` in ``Ok``, so ``Ok(false)`` (invalid KZG proof) is treated
as ``Ok(())`` (valid).  The fix binds the result and checks ``if !valid``.

Pattern IDs
-----------
* ``discarded_verify_bool`` — call ending in ``.map_err(...)? ;`` or bare
  ``call(...)? ;`` where the call name matches a crypto/verification pattern
  and the result is not bound to a variable.

Heuristics
----------
1. Detect lines of the form ``<expr>.map_err(<...>)?;`` (statement-level, not
   part of a ``let <x> = ...`` binding).
2. Also detect bare ``verify_kzg_proof(...)?;`` style (no map_err).
3. Narrow to function names that contain ``verify``, ``check``, ``validate``,
   ``assert``, ``kzg``, or ``proof``.

CLI: ``--workspace``, ``--strict``, ``--print-json``.
``--strict`` exits 1 when any row is emitted.

Examples
--------

::

    python3 tools/rust-discarded-verify-bool-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-discarded-verify-bool-scan.py \\
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


SCHEMA_VERSION = "auditooor.rust_discarded_verify_bool_scan.v1"

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

# Match lines that are statement-level ? applications (not bindings).
# Pattern: NOT starting with "let " or "return" (i.e., the result is dropped).
# Foot-gun #3: \b not ^.
#
# We look for: optional whitespace, then an expression containing a call with
# a verify/kzg/proof-like name, followed by .map_err(...)? ; or just ()? ;
# The key invariant is no ``let`` binding captures the result.

# Detect call chains ending in .map_err(...)? or just ? on a verify call.
# We match a line where:
# 1. There is no leading `let` binding.
# 2. The expression contains a verify/kzg/proof/check/validate function name.
# 3. The statement ends with `?;` (possibly with trailing whitespace).

VERIFY_CALL_NAMES = re.compile(
    r"\b(?:verify|check|validate|assert|kzg|proof)\w*\s*\(",
    re.IGNORECASE,
)

# A statement-level ?; — the result is thrown away.
# Match lines that end with ?; that are NOT let-bindings / return / control flow.
#
# Strategy: scan line-by-line.  A line ending with ?; is a candidate.
# Exclude lines where the trimmed content starts with:
#   let / return / assert / if / while / for / //
# Include lines starting with . (method chain continuation) that also end ?;
# — these are the "value.method()\n    .map_err(...)?" multi-line form.
#
# IMPORTANT: the lookahead fires at the START of the line (position 0) so we
# use ^(?!\s*let\b) which anchors at ^ and checks what follows including spaces.
STATEMENT_Q_RE = re.compile(
    r"^(?!\s*let\b)(?!\s*return\b)(?!\s*assert\b)"
    r"(?!\s*if\b)(?!\s*while\b)(?!\s*for\b)(?!\s*//)"
    r"\s*(?P<expr>[^\n;]+\?)\s*;[^\n]*$",
    re.MULTILINE,
)

# Additionally catch multi-line method chain continuations: a line starting with
# a dot (`.map_err(...)? ;`) that ends in ?;
CHAIN_Q_RE = re.compile(
    r"^\s*\.(?P<chain>[^\n;]+\?)\s*;[^\n]*$",
    re.MULTILINE,
)

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
    ("/succinct/", "untrusted_proof"),
    ("/precompile", "untrusted_proof"),
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VerifyRow:
    file: str
    line: int
    pattern_id: str
    containing_fn: str
    input_source: str
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


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[VerifyRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)
    rows: list[VerifyRow] = []

    seen_lines: set[int] = set()

    # Pattern 1: single-line statement-level ?; with verify call name.
    for m in STATEMENT_Q_RE.finditer(cleaned):
        expr = m.group("expr")
        if not VERIFY_CALL_NAMES.search(expr):
            continue
        abs_offset = m.start()
        line = _line_for_offset(cleaned, abs_offset)
        if line in seen_lines:
            continue
        seen_lines.add(line)
        fn_name = _enclosing_function(cleaned, abs_offset)
        rows.append(
            VerifyRow(
                file=rel,
                line=line,
                pattern_id="discarded_verify_bool",
                containing_fn=fn_name,
                input_source=src,
                snippet=_snippet(cleaned, abs_offset),
                confidence="high" if "kzg" in expr.lower() or "proof" in expr.lower() else "medium",
            )
        )

    # Pattern 2: multi-line method chain — line starting with `.` that ends `?;`
    # Look back one line to see if the preceding line contains a verify call.
    for m in CHAIN_Q_RE.finditer(cleaned):
        chain_expr = m.group("chain")
        abs_offset = m.start()
        line = _line_for_offset(cleaned, abs_offset)
        if line in seen_lines:
            continue
        # Look at the previous line for the verify call context.
        prev_line_end = cleaned.rfind("\n", 0, abs_offset)
        prev_line_start = cleaned.rfind("\n", 0, prev_line_end) + 1
        prev_line = cleaned[prev_line_start:prev_line_end]
        combined = prev_line + " " + chain_expr
        if not VERIFY_CALL_NAMES.search(combined):
            continue
        # Confirm the statement is not a let binding by checking the start of the
        # multi-line statement (prev_line must not be a let-binding line).
        if re.match(r"\s*let\b", prev_line):
            continue
        seen_lines.add(line)
        fn_name = _enclosing_function(cleaned, abs_offset)
        # Use the previous line's offset for the snippet (more informative).
        snippet_offset = prev_line_start
        rows.append(
            VerifyRow(
                file=rel,
                line=_line_for_offset(cleaned, prev_line_start),
                pattern_id="discarded_verify_bool",
                containing_fn=fn_name,
                input_source=src,
                snippet=_snippet(cleaned, snippet_offset),
                confidence="high" if "kzg" in combined.lower() or "proof" in combined.lower() else "medium",
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


def _count_by(rows: list[VerifyRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[VerifyRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[VerifyRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-discarded-verify-bool-scan.py",
        description=(
            "Wave H-3B — discarded Result<bool> from verify function scanner. "
            "Finds verify/kzg/proof calls where ? discards Ok(bool). "
            "Bug shape: patch a974aa35."
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
            f"[rust-discarded-verify-bool-scan] ERR workspace not a directory: {workspace}",
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
            f"[rust-discarded-verify-bool-scan] {len(rows)} row(s)",
            file=sys.stderr,
        )

    if args.strict and rows:
        print(
            f"[rust-discarded-verify-bool-scan] STRICT FAIL: {len(rows)} row(s)",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
