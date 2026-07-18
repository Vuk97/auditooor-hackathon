"""
staker-balance-rebase-vulnerability-unstake-before-positive-rebase.

Bug class: anchor-pda / rebase / accounting
Language:  vyper
Source:    solodit-2026-04-cycle32-vyper / Sherlock Yield Basis
Source URL: https://solodit.cyfrin.io/issues/h-1-staker-balance-rebase-vulnerability-in-lt-contract-sherlock-yield-basis-git

Semantic anchor:
  The balanceOf / total supply state is NOT updated immediately when
  a positive rebase event occurs — it is only updated lazily when
  `_calculate_values()` (or equivalent) is called.  A staker can call
  `unstake` BEFORE the rebase updates their balance to escape
  dilution / benefit from stale share accounting.

Detection strategy:
  Flag Vyper contracts where:
    1. A `balanceOf` or balance mapping reads state that is updated
       only via a separate `_calculate_values` / `_update_values` call.
    2. The `unstake` / `withdraw` function does NOT call the value-
       update helper BEFORE reading the staker's balance.

  Proxy signal: `unstake`/`withdraw` body does not contain a call to
  `_calculate_values` or equivalent BEFORE the balance read.

M14-trap note:
  The bug class is "unstake skips lazy-state update" — the predicate
  checks for the ABSENCE of the lazy-update call in the withdraw path,
  not for a specific fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_UNSTAKE_FN_RE = re.compile(
    r"def\s+(unstake|withdraw|exit|redeem|burn_and_exit)\s*\(",
    re.IGNORECASE,
)

# The lazy-update helper that MUST be called before balance read
_LAZY_UPDATE_RE = re.compile(
    r"(?:_calculate_values|_update_values|_update_balances|"
    r"_checkpoint|_sync_rebase|_apply_rebase|_settle_rebase)\s*\(",
    re.IGNORECASE,
)

# Balance read inside unstake (indicating the stale-read path)
_BALANCE_READ_RE = re.compile(
    r"\b(?:balanceOf|self\.balances|staked_balance|user_balance|"
    r"position\.balance)\b",
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
    for m in _UNSTAKE_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        reads_balance = bool(_BALANCE_READ_RE.search(body))
        calls_lazy = bool(_LAZY_UPDATE_RE.search(body))
        if reads_balance and not calls_lazy:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` reads staker balance without calling the lazy "
                    "rebase / value-update helper first. A staker can exit before "
                    "a positive rebase is applied, escaping dilution or receiving "
                    "stale accounting."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect lazy-rebase skip in Vyper unstake functions."
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
