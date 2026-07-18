"""
fewer-lp-tokens-when-pool-imbalanced-during-vault-restoration.

Bug class: dex-integration / slippage
Language:  vyper
Source:    solodit-2026-04-cycle32-vyper / Sherlock Notional
Source URL: https://solodit.cyfrin.io/issues/h-4-fewer-than-expected-lp-tokens-if-the-pool-is-imbalanced-during-vault-restoration-sherlock-notional-update-4-git

Semantic anchor:
  During vault restoration the code always performs a proportional
  deposit into a Curve pool — `add_liquidity` with all token amounts
  set.  When the pool is imbalanced, a proportional deposit yields
  fewer LP tokens than a single-sided deposit would.  The protocol
  should detect imbalance and switch to the single-side path.

Detection strategy:
  Flag Vyper contracts where:
    1. A restore / reinvest / rebalance function calls `add_liquidity`
       (or equivalent) with multiple non-zero token amounts (proportional).
    2. There is NO imbalance check (pool balance ratio, reserves check,
       or conditional dispatch to add_liquidity_one_coin) before the call.

  Proxy signal: `add_liquidity` called with an array literal / all
  amounts set, and no conditional branch on pool imbalance precedes it.

M14-trap note:
  Bug class is "unconditional proportional deposit ignores pool state" —
  the predicate checks for the ABSENCE of an imbalance-conditional
  before add_liquidity, not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_RESTORE_FN_RE = re.compile(
    r"def\s+(restore|reinvest|rebalance|_restore|_reinvest)\s*\(",
    re.IGNORECASE,
)

# Proportional add_liquidity call (multi-token array)
_ADD_LIQ_RE = re.compile(r"\badd_liquidity\s*\(", re.IGNORECASE)

# Imbalance guard / check before deposit (the fix)
_IMBALANCE_CHECK_RE = re.compile(
    r"(?:is_imbalanced|pool_imbalanced|ratio\s*[><]=?|"
    r"add_liquidity_one_coin|single_side_deposit|"
    r"balances\[0\]\s*/\s*balances\[1\]|"
    r"if\s+\w+\s*>\s*\w+.*:\s*\n\s*add_liquidity_one)",
    re.IGNORECASE,
)


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_fn_body(source: str, fn_start: int) -> str:
    lines = source[fn_start:].split("\n")
    if not lines:
        return ""
    base_indent = len(lines[0]) - len(lines[0].lstrip())
    body_lines: list[str] = [lines[0]]
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "":
            body_lines.append(line)
            continue
        curr_indent = len(line) - len(line.lstrip())
        if curr_indent <= base_indent and stripped:
            break
        body_lines.append(line)
    return "\n".join(body_lines)


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _RESTORE_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        if not _ADD_LIQ_RE.search(body):
            continue
        if not _IMBALANCE_CHECK_RE.search(body):
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` always performs a proportional `add_liquidity` "
                    "without checking pool balance. When the pool is imbalanced, "
                    "a proportional deposit yields sub-optimal LP tokens. "
                    "Should detect imbalance and switch to single-side deposit."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect proportional deposit without imbalance check in Vyper vault restoration."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    hits: list[dict] = []
    for p in args.paths:
        if p.is_dir():
            for f in sorted(p.rglob("*.vy")):
                hits.extend(scan_file(f))
        elif p.suffix in (".vy", ".vyper"):
            hits.extend(scan_file(p))
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['filepath']}:{h['line']}: {h['severity']}: {h['message']}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
