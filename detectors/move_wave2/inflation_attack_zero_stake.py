"""
inflation-attack-on-zero-total-stake-staking-v2.

Bug class: token-standard / inflation-attack
Language:  move (Aptos)
Source:    solodit-2026-04-cycle20-move / OtterSec Thala LSD
Source URL: https://solodit.cyfrin.io/issues/inflation-attack-on-zero-total-stake-ottersec-none-thala-lsd-deps-pdf

Semantic anchor:
  `staking::stake_thAPT_v2` allows the FIRST depositor to manipulate
  the exchange rate by using a staking fee to depeg the 1:1 thAPT:stAPT
  ratio.  When `total_stake == 0`, the shares-per-token calculation can
  be manipulated so subsequent depositors receive zero shares (or the
  attacker gains disproportionate shares).

Detection strategy:
  Flag Move staking functions where:
    1. Shares are minted based on a ratio `amount * total_shares / total_stake`.
    2. There is NO guard against `total_stake == 0` or a minimum-deposit
       / initial-share seeding mechanism.

  Proxy signal: shares_to_mint computed via division by `total_stake`
  without an `if total_stake == 0` guard providing a fixed initial ratio.

M14-trap note:
  Bug class is "share inflation when total_stake=0 allows first-depositor
  manipulation" — predicate checks for ABSENT zero-stake guard in the
  share-minting calculation, not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_STAKE_FN_RE = re.compile(
    r"fun\s+(stake|deposit|mint_shares|add_liquidity|stake_thAPT|"
    r"stake_v2|deposit_v2)\s*[(<]",
    re.IGNORECASE,
)

# Shares computed by dividing by total_stake (vulnerable ratio formula)
# Allow dots in field access (pool.total_shares, pool.total_stake)
_SHARES_RATIO_RE = re.compile(
    r"\*\s*[\w.]*(?:total_shares|shares_outstanding|total_supply)[\w.]*\s*/"
    r"\s*[\w.]*(?:total_stake|total_assets|total_locked|reserve)[\w.]*",
    re.IGNORECASE,
)

# Zero-stake guard (the fix)
_ZERO_GUARD_RE = re.compile(
    r"(?:if\s+[\w.]*(?:total_stake|total_assets)[\w.]*\s*==\s*0|"
    r"total_stake\s*==\s*0\s*=>|"
    r"assert!\s*\(\s*[\w.]*(?:total_stake|total_assets)[\w.]*\s*>\s*0|"
    r"minimum_deposit|initial_shares|INITIAL_SUPPLY|INITIAL_SHARES)",
    re.IGNORECASE,
)


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_fn_body(source: str, fn_start: int) -> str:
    idx = source.find("{", fn_start)
    if idx == -1:
        return ""
    depth = 0
    for i in range(idx, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[fn_start:i + 1]
    return source[fn_start:]


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_comments(s: str) -> str:
    return _LINE_COMMENT_RE.sub("", s)


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _STAKE_FN_RE.finditer(source):
        body = _strip_comments(_extract_fn_body(source, m.start()))
        has_ratio = bool(_SHARES_RATIO_RE.search(body))
        has_guard = bool(_ZERO_GUARD_RE.search(body))
        if has_ratio and not has_guard:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "medium",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` computes shares via `amount * total_shares / total_stake` "
                    "without guarding against `total_stake == 0`. The first depositor "
                    "can manipulate the exchange rate (inflation attack)."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect inflation attack risk in Move staking on zero total-stake."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    hits: list[dict] = []
    for p in args.paths:
        if p.is_dir():
            for f in sorted(p.rglob("*.move")):
                hits.extend(scan_file(f))
        elif p.suffix == ".move":
            hits.extend(scan_file(p))
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['filepath']}:{h['line']}: {h['severity']}: {h['message']}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
