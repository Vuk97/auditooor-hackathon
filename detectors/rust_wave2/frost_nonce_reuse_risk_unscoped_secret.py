#!/usr/bin/env python3
"""
frost_nonce_reuse_risk_unscoped_secret — wave-2 FROST detector.

Detects FROST signing functions that consume a ``&SigningNonces`` parameter
(or produce one via ``SigningNonces::new`` / ``Nonce::new`` / ``from_nonces``)
without any freshness guard.  Absence of a freshness check means a caller can
reuse the same nonce across multiple signing rounds — leaking the long-lived
signing share.

Pattern (positive / flagged):
  * Function signature contains a ``SigningNonces`` parameter *or* the function
    body creates ``SigningNonces``/``Nonce`` via ``new(`` / ``from_nonces(``.
  * The body does NOT contain any freshness-guard marker:
    ``is_fresh``, ``assert_used_once``, ``nonce_used``,
    ``mark_used``, ``mark_nonce_used``, or a ``used`` boolean flag
    on the nonce.

Pattern (negative / clean):
  * Any of the above guard markers is present in the body.

Detection is line-level within matching functions.  We report the line of the
``fn`` header.

Usage::

    python3 frost_nonce_reuse_risk_unscoped_secret.py <path>

Outputs one line per hit::

    <file>:<line>:frost_nonce_reuse_risk_unscoped_secret:<message>

Exit 0 always (presence/absence communicated via output lines).
"""
from __future__ import annotations

import os
import re
import sys

DETECTOR_ID = "frost_nonce_reuse_risk_unscoped_secret"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

# Matches a fn header line (may be public / async / unsafe / generic).
_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:async\s+|unsafe\s+|const\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
)

# Indicates the function deals with signing nonces.
_NONCE_SIGNAL_RE = re.compile(
    r"\bSigningNonces\b"
    r"|\bSigningNonces::\s*new\s*\("
    r"|\bNonce::\s*new\s*\("
    r"|\bfrom_nonces\s*\("
    r"|\bsigner_nonces\b"
)

# Any of these in the body means the author added a freshness guard.
_FRESHNESS_GUARD_RE = re.compile(
    r"\bis_fresh\s*\("
    r"|\bassert_used_once\s*\("
    r"|\bnonce_used\b"
    r"|\bmark_used\s*\("
    r"|\bmark_nonce_used\s*\("
    r"|\bused\s*=\s*true\b"
    r"|\bused\s*=\s*false\b"
    r"|\bcheck_nonce_freshness\s*\("
)


def _collect_function_blocks(lines: list[str]) -> list[tuple[int, str, str]]:
    """Return list of (start_line_1indexed, fn_name, body_text)."""
    results = []
    i = 0
    n = len(lines)
    while i < n:
        m = _FN_HEADER_RE.match(lines[i])
        if m:
            fn_name = m.group("name")
            fn_start = i + 1  # 1-indexed
            # Scan forward to the opening brace.
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
    """Return list of (line_1indexed, message)."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    lines = content.splitlines()
    hits = []
    for start_line, fn_name, body in _collect_function_blocks(lines):
        # Must have a nonce signal in the params or body.
        combined = "\n".join(lines[max(0, start_line - 1):start_line]) + "\n" + body
        if not _NONCE_SIGNAL_RE.search(combined):
            continue
        # Skip if a freshness guard is present.
        if _FRESHNESS_GUARD_RE.search(body):
            continue
        # Skip tiny stubs (fewer than 3 body lines).
        if body.count("\n") < 2:
            continue
        hits.append((
            start_line,
            f"fn `{fn_name}` consumes SigningNonces without a freshness guard "
            f"(is_fresh / mark_used / nonce_used) — nonce reuse risk.",
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
