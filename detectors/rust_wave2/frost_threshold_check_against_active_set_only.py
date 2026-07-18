#!/usr/bin/env python3
"""
frost_threshold_check_against_active_set_only — wave-2 FROST detector.

Detects threshold checks of the form::

    if signers.len() >= self.threshold { ... }

that use the *raw active-set count* rather than a deduplicated signer-identifier
count.  An attacker controlling the signing coordinator can supply duplicate
``Identifier`` values in the signer list to satisfy ``signers.len() >= threshold``
while only having ``threshold - k`` distinct signers, effectively bypassing the
threshold requirement.

Pattern (positive / flagged):
  * A ``.len()`` comparison against a field or variable named ``threshold`` /
    ``min_signers`` / ``MIN_SIGNERS`` WITHOUT a preceding ``HashSet`` /
    ``BTreeSet`` dedup or a ``.iter().map(|s| s.identifier).collect::<HashSet``
    style dedup in the same function body.

Pattern (negative / clean):
  * Same threshold check is present BUT the function also deduplicates
    identifiers via ``HashSet`` / ``BTreeSet`` / ``.dedup()`` before the check.

Usage::

    python3 frost_threshold_check_against_active_set_only.py <path>

Outputs one line per hit::

    <file>:<line>:frost_threshold_check_against_active_set_only:<message>

Exit 0 always.
"""
from __future__ import annotations

import os
import re
import sys

DETECTOR_ID = "frost_threshold_check_against_active_set_only"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:async\s+|unsafe\s+|const\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
)

# A raw-count threshold check: <expr>.len() >= <threshold_var>
# We accept >= or > comparisons (both are logically equivalent threshold tests).
_RAW_THRESHOLD_CHECK_RE = re.compile(
    r"\.\s*len\s*\(\s*\)\s*(?:>=|>)\s*"
    r"(?:\w+\.)?"          # optional qualifier: self., key_package., config., etc.
    r"(?:threshold|min_signers|MIN_SIGNERS|signers_threshold|Threshold)"
    r"\b"
)

# Dedup guard: any of these indicates the author deduplicated identifiers
# before the threshold check.
_DEDUP_GUARD_RE = re.compile(
    r"\bHashSet\s*::<"
    r"|\bBTreeSet\s*::<"
    r"|\bHashSet\s*::new\s*\("
    r"|\bBTreeSet\s*::new\s*\("
    r"|\.collect\s*::<\s*HashSet"
    r"|\.collect\s*::<\s*BTreeSet"
    r"|\.dedup\s*\("
    r"|\.into_iter\s*\(\s*\)\s*\.\s*collect\s*::<\s*(?:Hash|BTree)Set"
    r"|\bidentifiers?\s*\.\s*into_iter"
    r"|\bdeduped\b"
    r"|\bdedup_signers\b"
)


def _collect_function_blocks(lines: list[str]) -> list[tuple[int, str, str]]:
    results = []
    i = 0
    n = len(lines)
    while i < n:
        m = _FN_HEADER_RE.match(lines[i])
        if m:
            fn_name = m.group("name")
            fn_start = i + 1  # 1-indexed
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
        if not _RAW_THRESHOLD_CHECK_RE.search(body):
            continue
        # Skip if a dedup guard is present in the same body.
        if _DEDUP_GUARD_RE.search(body):
            continue
        # Skip tiny stubs.
        if body.count("\n") < 2:
            continue
        hits.append((
            start_line,
            f"fn `{fn_name}` checks `signers.len() >= threshold` on the raw "
            f"active-set count without deduplicating identifiers — "
            f"duplicate-signer replay can satisfy the threshold check.",
        ))
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
