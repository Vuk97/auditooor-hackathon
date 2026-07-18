#!/usr/bin/env python3
"""Rust Option<Vec<T>>::iter().all/.any misclassifier scanner — Wave I-1D / G-v01.

Bug shape
---------
``Option<Vec<T>>::iter()`` yields the inner ``Vec<T>`` *once* when the Option is
``Some``, or yields nothing when ``None``.  Chaining ``.all(|v| ...)`` or
``.any(|v| ...)`` therefore runs the closure *once* — with the closure parameter
bound to the **whole Vec**, not to an individual element.

The classic mistake is writing:

.. code-block:: rust

    transactions
        .iter()                        // ← iterates over Option, not Vec elements
        .all(|tx| tx.first() == Some(&0x7E))

thinking that ``tx`` is a transaction byte-slice.  In reality ``tx`` is the whole
``Vec<Bytes>`` (or ``&Vec<Bytes>``), and ``tx.first()`` returns the *first* element
of the Vec — i.e., only ``tx[0]`` is ever tested.  All remaining elements are silently
skipped.

Audit-snapshot reference
------------------------
``external/base/crates/consensus/protocol/src/attributes.rs:65-70``::

    pub fn is_deposits_only(&self) -> bool {
        self.attributes
            .transactions
            .iter()                                    // ← BUG
            .all(|tx| tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8))
    }

``transactions`` is ``Option<&Vec<Bytes>>``.  The ``iter()`` call returns an
``std::option::Iter`` that yields ``&Vec<Bytes>`` once.  The closure gets the
whole Vec; ``tx.first()`` / ``tx[0]`` checks only byte-0 of the first element.
Non-deposit transactions at any position other than index-0 are never checked.

Pattern IDs
-----------
* ``iter_all_first_only``  — ``.iter().all(…)`` where the closure indexes only the
  first element of what was supposed to be iterated.
* ``iter_any_first_only``  — same with ``.any(…)``.

Confidence levels
-----------------
* ``high``   — the receiver expression is plausibly an Option (name contains
  ``transaction``, ``tx``, ``payload``, ``deposit``, ``block``, ``opt``) AND
  the closure body contains ``.first()``, ``[0]``, or ``.iter().next()``.
* ``medium`` — ``.iter().all/any(…)`` where the closure uses a first-element
  index but the receiver type cannot be confirmed as Option<Vec<…>>.

Default-to-kill discipline
--------------------------
Every row carries ``candidate_status = "kill_or_reframe"``.
``--strict`` exits non-zero when any row is emitted.

CLI
---
``--workspace``, ``--strict``, ``--print-json``

Examples
--------
::

    python3 tools/rust-option-iter-misclassifier-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-option-iter-misclassifier-scan.py \\
        --workspace ~/audits/base-azul --strict
    make rust-option-iter-misclassifier-scan WS=~/audits/base-azul
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
    try:
        from lib.project_source_roots import rust_crate_scan_roots
    except ModuleNotFoundError:
        rust_crate_scan_roots = None  # type: ignore[assignment]


SCHEMA_VERSION = "auditooor.rust_option_iter_misclassifier.v1"

DEFAULT_SCAN_ROOTS = (
    "external/base/crates",
    "crates",
)

# ---------------------------------------------------------------------------
# Path exclusions
# ---------------------------------------------------------------------------

TEST_PATH_TOKENS = (
    "/tests/",
    "/test_",
    "/testing/",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
)

# Option-looking receiver names — receiver expressions that suggest an Option<Vec>
# type.  We match case-insensitively against the chain before ``.iter()``.
# Note: use (?<!\w) / (?!\w) instead of \b so that `.transactions` (dot-prefixed)
# matches correctly even when the leading char is a non-word dot.
# Include plural forms explicitly (transactions, deposits, etc.).
OPTION_VEC_NAMES = re.compile(
    r"(?<!\w)(?:transactions?|txs?|payload|deposits?|blocks?|opt|items?|lists?|"
    r"entries?|data|bytes?|ops?|receipts?|logs?|withdrawals?)(?!\w)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Pattern compilation
# Foot-gun #3: \b not ^
# ---------------------------------------------------------------------------

# Core pattern: <expr>.iter().<all|any>(|<param>| <body>)
# We use a two-pass approach:
#   Pass 1 — find .iter().all( or .iter().any(  positions.
#   Pass 2 — extract the closure body (up to the matching paren).
ITER_ALL_RE = re.compile(r"\.\s*iter\s*\(\s*\)\s*\.\s*all\s*\(")
ITER_ANY_RE = re.compile(r"\.\s*iter\s*\(\s*\)\s*\.\s*any\s*\(")

# Closure parameter pattern:  |param_name|  or  |param_name: type|
CLOSURE_PARAM_RE = re.compile(r"\|\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*:[^|]*)?\s*\|")

# First-element access patterns in a closure body.
# Note: do NOT use \b before the leading dot — a dot is a non-word char and
# \b would fail to anchor after spaces/other non-word chars.  Use a simple
# non-capturing group without \b prefix.
FIRST_ELEM_RE = re.compile(
    r"(?:"
    # .first()  — method call on the closure param (may have trailing .is_some_and etc.)
    r"(?P<first_method>\.first\s*\(\s*\))"
    r"|"
    # [0] direct index
    r"(?P<index_zero>\[\s*0\s*\])"
    r"|"
    # .iter().next()  on the closure param
    r"(?P<iter_next>\.iter\s*\(\s*\)\s*\.\s*next\s*\(\s*\))"
    r")"
)

# Safe patterns: correctly unwraps Option before iterating.
# If any of these appear in the line (or the small surrounding context),
# the match is considered clean.
SAFE_PATTERNS_RE = re.compile(
    r"\b(?:"
    r"unwrap_or\s*\("
    r"|as_ref\s*\(\s*\)\s*\.\s*(?:map|and_then|is_some_and|iter)"
    r"|flatten\s*\(\s*\)"
    r"|is_some_and\s*\("
    r"|map\s*\(\s*\|"
    r")\b"
)

# Receiver expression capture — walk backwards from .iter() to grab the
# receiver chain.  We look at the 120 chars before the .iter() call.
RECEIVER_LOOKBACK = 120

# Function declaration boundary (Foot-gun #3: \b).
FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class MisclassifierRow:
    file: str
    line: int
    pattern_id: str
    containing_fn: str
    confidence: str
    snippet: str
    receiver_expr: str
    closure_param: str
    first_elem_access: str
    recommendation: str = (
        "Replace .iter().all/any(|v| v.first()…) with "
        ".as_ref().map_or(true, |vec| vec.iter().all/any(|elem| …)) "
        "to iterate over Vec elements rather than the Option wrapper."
    )
    candidate_status: str = "kill_or_reframe"
    submission_posture: str = "NOT_SUBMIT_READY"
    evidence_class: str = "detector_hit"


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


def _strip_test_blocks(text: str) -> str:
    """Remove #[cfg(test)] mod blocks so we don't flag test code."""
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


def _extract_closure_body(text: str, start_offset: int) -> str:
    """Extract up to 200 chars of closure body starting after the opening '('."""
    # Find the pipe-delimited parameter list then extract up to closing paren depth.
    i = start_offset
    n = len(text)
    depth = 1
    body_chars: list[str] = []
    while i < n and depth > 0 and len(body_chars) < 200:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        body_chars.append(c)
        i += 1
    return "".join(body_chars)


def _receiver_expr(text: str, iter_match_start: int) -> str:
    """Grab the receiver chain immediately before .iter()."""
    look_start = max(0, iter_match_start - RECEIVER_LOOKBACK)
    fragment = text[look_start:iter_match_start]
    # Strip trailing whitespace/newlines.
    fragment = fragment.rstrip()
    # We want the last dotted-chain or identifier sequence.
    # Simple heuristic: take from the last newline or semicolon.
    for sep in ("\n", ";", "{", "}", "("):
        idx = fragment.rfind(sep)
        if idx != -1:
            fragment = fragment[idx + 1 :]
    return fragment.strip()[-80:]  # cap at 80 chars


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[MisclassifierRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    rows: list[MisclassifierRow] = []
    seen_lines: set[int] = set()

    for pattern_re, pattern_id in [
        (ITER_ALL_RE, "iter_all_first_only"),
        (ITER_ANY_RE, "iter_any_first_only"),
    ]:
        for m in pattern_re.finditer(cleaned):
            match_start = m.start()
            # The .all( or .any( opening paren is at m.end() - 1.
            closure_start = m.end() - 1  # points at '('

            line = _line_for_offset(cleaned, match_start)
            if line in seen_lines:
                continue

            # Extract closure body.
            closure_body = _extract_closure_body(cleaned, closure_start + 1)

            # Extract closure parameter name.
            cp_m = CLOSURE_PARAM_RE.search(closure_body)
            if not cp_m:
                continue
            closure_param = cp_m.group(1)

            # Check for first-element access in the closure body.
            fea_m = FIRST_ELEM_RE.search(closure_body)
            if not fea_m:
                continue
            first_elem_access = closure_body[fea_m.start() : fea_m.end()].strip()

            # Check for safe patterns that would make this a false positive.
            # Look backwards 200 chars (to catch as_ref().is_some_and before
            # the .iter().all) and forwards 300 chars (for flatten after).
            window_start = max(0, match_start - 200)
            window_end = min(len(cleaned), m.end() + 300)
            window = cleaned[window_start:window_end]

            # Suppress if a genuine-unwrap safe pattern is present in the window.
            # "flatten" is its own safe pattern; as_ref/unwrap_or/is_some_and are
            # suppressed independently (not gated on flatten).
            if SAFE_PATTERNS_RE.search(window):
                continue

            # Determine confidence based on receiver expression.
            recv = _receiver_expr(cleaned, match_start)
            is_option_shaped = bool(OPTION_VEC_NAMES.search(recv))
            confidence = "high" if is_option_shaped else "medium"

            containing_fn = _enclosing_function(cleaned, match_start)
            snip = _snippet(cleaned, match_start)

            rows.append(
                MisclassifierRow(
                    file=rel,
                    line=line,
                    pattern_id=pattern_id,
                    containing_fn=containing_fn,
                    confidence=confidence,
                    snippet=snip,
                    receiver_expr=recv,
                    closure_param=closure_param,
                    first_elem_access=first_elem_access,
                )
            )
            seen_lines.add(line)

    return rows


# ---------------------------------------------------------------------------
# Workspace walk
# ---------------------------------------------------------------------------


def scan_workspace(workspace: Path, strict: bool = False) -> list[MisclassifierRow]:
    all_rows: list[MisclassifierRow] = []

    # Determine scan roots.
    scan_roots: list[Path] = []
    if rust_crate_scan_roots is not None:
        try:
            scan_roots = [Path(r) for r in rust_crate_scan_roots(workspace)]
        except Exception:
            pass

    if not scan_roots:
        for root_rel in DEFAULT_SCAN_ROOTS:
            candidate = workspace / root_rel
            if candidate.is_dir():
                scan_roots.append(candidate)

    if not scan_roots:
        # Fallback: scan the whole workspace.
        scan_roots = [workspace]

    for root in scan_roots:
        for rs_file in sorted(root.rglob("*.rs")):
            rel = _safe_rel(rs_file, workspace)
            # Skip test paths.
            if any(tok in "/" + rel for tok in TEST_PATH_TOKENS):
                continue
            all_rows.extend(scan_file(rs_file, workspace))

    return all_rows


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def emit_text(rows: list[MisclassifierRow]) -> None:
    if not rows:
        print("[rust-option-iter-misclassifier-scan] OK — no hits")
        return
    for r in rows:
        print(
            f"[{r.confidence.upper()}] {r.file}:{r.line} "
            f"pattern={r.pattern_id} fn={r.containing_fn}"
        )
        print(f"  snippet  : {r.snippet}")
        print(f"  receiver : {r.receiver_expr}")
        print(f"  closure  : |{r.closure_param}| … {r.first_elem_access}")
        print(f"  status   : {r.candidate_status}")
        print()


def emit_json(rows: list[MisclassifierRow]) -> None:
    payload = {
        "schema": SCHEMA_VERSION,
        "row_count": len(rows),
        "rows": [asdict(r) for r in rows],
    }
    print(json.dumps(payload, indent=2))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Rust crates for Option::iter().all/any misclassifier pattern (G-v01)."
    )
    parser.add_argument("--workspace", required=True, help="Path to workspace root.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any row is emitted (CI gate mode).",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Emit JSON output (schema: auditooor.rust_option_iter_misclassifier.v1).",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-option-iter-misclassifier-scan] ERR workspace not found: {workspace}")
        return 2

    rows = scan_workspace(workspace, strict=args.strict)

    if args.print_json:
        emit_json(rows)
    else:
        emit_text(rows)

    if args.strict and rows:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
