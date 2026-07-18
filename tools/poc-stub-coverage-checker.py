#!/usr/bin/env python3
"""poc-stub-coverage-checker.py — T-04.

For any paste-ready PoC that uses `*Stub*` / `*Mock*` contracts, require
inline documentation of which production checks are faithfully modeled vs
intentionally simplified. Reference: FN2's PortalStub modeled 6 of 7
OptimismPortal2 production checks faithfully (the SecureMerkleTrie inclusion
proof was replaced with a registeredWithdrawals map + explicit reasoning
paragraph).

Rule (FN2 lesson, codified):
  When a PoC uses a Stub or Mock contract, the paste-ready MUST contain
  inline documentation per stub explaining:
    - Which production checks the stub faithfully reproduces.
    - Which production checks (if any) are intentionally simplified, with
      justification (why simplification preserves the impact claim).

Usage:
  python3 tools/poc-stub-coverage-checker.py <draft.md>

Exit codes:
  0  no stubs found OR all stubs have coverage doc
  1  one or more stubs are missing coverage documentation
  2  invalid args / file not found
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# Match `contract <Name>Stub` or `contract <Name>Mock` or `contract Mock<Name>`
# inside Solidity blocks (between triple-backticks).
_STUB_PATTERNS = [
    re.compile(r"\bcontract\s+(\w*Stub\w*)\b"),
    re.compile(r"\bcontract\s+(\w*Mock\w*)\b"),
    re.compile(r"\bcontract\s+(Stub\w*)\b"),
    re.compile(r"\bcontract\s+(Mock\w*)\b"),
]

# Phrases that indicate the author has documented stub coverage. Any of these
# within ±60 lines of the stub declaration counts as covered.
_COVERAGE_PHRASES = [
    r"production\s+check",
    r"faithfully\s+model",
    r"faithfully\s+reproduce",
    r"intentionally\s+simplified",
    r"\d+\s+of\s+\d+\s+(production|checks)",  # "6 of 7 OptimismPortal2 checks"
    r"stub\s+models",
    r"mock\s+models",
    r"why\s+(this\s+)?simplification",
    r"(replicates|matches)\s+(the\s+)?production",
    r"(this|the)\s+stub\s+(implements|reproduces)",
    r"(this|the)\s+mock\s+(implements|reproduces)",
    r"trust\s+assumption",
    r"replaced\s+with\s+a?\s*\w+",
]


def find_stubs_with_lines(text: str) -> list[tuple[str, int]]:
    """Return [(stub_name, line_number)] for every contract Stub/Mock in code blocks."""
    results: list[tuple[str, int]] = []
    in_code = False
    for i, line in enumerate(text.splitlines(), start=1):
        if line.startswith("```"):
            in_code = not in_code
            continue
        if not in_code:
            continue
        for pat in _STUB_PATTERNS:
            for m in pat.finditer(line):
                results.append((m.group(1), i))
    return results


def has_coverage_doc(text_lines: list[str], stub_line: int, window: int = 60) -> tuple[bool, str | None]:
    """Look for any coverage phrase within ±window lines of stub_line."""
    lo = max(1, stub_line - window) - 1
    hi = min(len(text_lines), stub_line + window)
    snippet = "\n".join(text_lines[lo:hi])
    for phrase_re in _COVERAGE_PHRASES:
        m = re.search(phrase_re, snippet, re.IGNORECASE)
        if m:
            return True, phrase_re
    return False, None


def check_draft(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    text_lines = text.splitlines()
    stubs = find_stubs_with_lines(text)

    print(f"[poc-stub-coverage] file: {path}")
    print(f"[poc-stub-coverage] stub/mock contracts found in code blocks: {len(stubs)}")

    if not stubs:
        print("[poc-stub-coverage] no stubs/mocks found — nothing to check; PASS")
        return 0

    missing: list[tuple[str, int]] = []
    for name, line in stubs:
        ok, phrase = has_coverage_doc(text_lines, line)
        flag = "OK" if ok else "MISSING"
        detail = f"matched '{phrase}'" if ok else "no coverage phrase within ±60 lines"
        print(f"  {flag:8} {name} (line {line}) — {detail}")
        if not ok:
            missing.append((name, line))

    if missing:
        print()
        print(f"[poc-stub-coverage] FAIL: {len(missing)} stub(s) missing coverage documentation.")
        print()
        print("Required: for each Stub/Mock contract, the paste-ready text within ±60 lines")
        print("of the contract declaration MUST explain which production checks are")
        print("faithfully reproduced AND which (if any) are intentionally simplified, with")
        print("justification.")
        print()
        print("Reference: FN2's PortalStub. 6 of 7 OptimismPortal2 production checks were")
        print("faithfully modeled; the SecureMerkleTrie inclusion proof was replaced with")
        print("a `registeredWithdrawals` map plus an explicit reasoning paragraph stating")
        print("why this simplification does not weaken the impact claim (the attacker has")
        print("access to chain-A state trie to construct a real MPT proof off-chain).")
        return 1

    print("[poc-stub-coverage] PASS: all stubs have coverage documentation.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("draft", help="Path to paste-ready markdown")
    args = ap.parse_args()
    path = Path(args.draft)
    if not path.exists():
        print(f"[poc-stub-coverage] file not found: {path}", file=sys.stderr)
        return 2
    return check_draft(path)


if __name__ == "__main__":
    sys.exit(main())
