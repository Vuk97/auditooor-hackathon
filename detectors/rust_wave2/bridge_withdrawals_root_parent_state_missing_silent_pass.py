#!/usr/bin/env python3
"""
bridge_withdrawals_root_parent_state_missing_silent_pass

Narrow Rust detector for the confirmed Base FN7 shape in the
bridge-proof-domain-bypass family.

Confirmed corpus basis:
  - legacy:paste_ready_fn7-critical-candidate-paste.md:a05a26cea65b
  - docs/archive/2026-05/FN7_EXPLOITABILITY_RESEARCH_2026-04-29.md
  - reference/patterns.dsl/r78_reth_chain/base-isthmus-withdrawals-root-parent-state-skip.yaml

Pattern (positive / flagged):
  * Rust impl function named `validate_block_post_execution_with_hashed_state`
  * Isthmus-gated path is present
  * parent state is loaded with `state_by_block_hash(...parent_hash...)`
  * lookup failure returns `Ok(())`
  * same function contains a `verify_withdrawals_root*` call

Pattern (negative / clean):
  * same validation path is present, but missing parent state fails closed
    via `map_err`, `Err(...)`, `return Err(...)`, or equivalent.

Usage:
  python3 bridge_withdrawals_root_parent_state_missing_silent_pass.py <path>

Output:
  <file>:<line>:bridge_withdrawals_root_parent_state_missing_silent_pass:<message>

Exit 0 always.
"""
from __future__ import annotations

import os
import re
import sys

DETECTOR_ID = "bridge_withdrawals_root_parent_state_missing_silent_pass"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:async\s+|unsafe\s+|const\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
)

_TARGET_FN_NAME = "validate_block_post_execution_with_hashed_state"
_ISTHMUS_SIGNAL_RE = re.compile(r"\bis_isthmus_active_at_timestamp\s*\(")
_PARENT_LOOKUP_RE = re.compile(
    r"\bstate_by_block_hash\s*\([^)]*(?:parent_hash\s*\(|block\s*\.\s*parent_hash\s*\()"
)
_SILENT_OK_RE = re.compile(
    r"let\s+Ok\s*\(\s*\w+\s*\)\s*=\s*.*?state_by_block_hash.*?else\s*\{[^{}]*return\s+Ok\s*\(\s*\(\s*\)\s*\)\s*;[^{}]*\}",
    re.DOTALL,
)
_VERIFY_CALL_RE = re.compile(r"\bverify_withdrawals_root(?:_prehashed)?\s*\(")


def _collect_function_blocks(lines: list[str]) -> list[tuple[int, str, str]]:
    results = []
    i = 0
    n = len(lines)
    while i < n:
        m = _FN_HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        fn_name = m.group("name")
        fn_start = i + 1
        brace_depth = 0
        body_start = None
        j = i
        while j < n:
            for ch in lines[j]:
                if ch == "{":
                    if brace_depth == 0:
                        body_start = j
                    brace_depth += 1
                elif ch == "}":
                    brace_depth -= 1
                    if brace_depth == 0 and body_start is not None:
                        body = "\n".join(lines[body_start:j + 1])
                        results.append((fn_start, fn_name, body))
                        i = j
                        break
            else:
                j += 1
                continue
            break
        i += 1
    return results


def scan_file(filepath: str) -> list[tuple[int, str]]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    lines = content.splitlines()
    hits = []
    for start_line, fn_name, body in _collect_function_blocks(lines):
        if fn_name != _TARGET_FN_NAME:
            continue
        if not _ISTHMUS_SIGNAL_RE.search(body):
            continue
        if not _PARENT_LOOKUP_RE.search(body):
            continue
        if not _VERIFY_CALL_RE.search(body):
            continue
        if not _SILENT_OK_RE.search(body):
            continue
        hits.append(
            (
                start_line,
                "fn `validate_block_post_execution_with_hashed_state` returns "
                "`Ok(())` when `state_by_block_hash(parent_hash)` fails in the "
                "post-Isthmus withdrawals-root validation path, silently "
                "skipping the bridge/domain check.",
            )
        )
    return hits


def scan(root: str) -> list[tuple[str, int, str]]:
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(".rs"):
                continue
            fpath = os.path.join(dirpath, fname)
            for line, msg in scan_file(fpath):
                results.append((fpath, line, msg))
    return results


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(f"usage: {sys.argv[0]} <path>", file=sys.stderr)
        return 2
    root = args[0]
    hits = scan(root)
    for fpath, line, msg in hits:
        print(f"{fpath}:{line}:{DETECTOR_ID}:{msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
