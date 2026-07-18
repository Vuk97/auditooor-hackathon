"""
inflation-attack-on-zero-total-stake-staking-v2.

Bug class: token-standard / share-inflation
Language:  move (Aptos)
Source:    solodit-2026-04-cycle20-move / OtterSec Thala LSD
Source URL: https://solodit.cyfrin.io/issues/inflation-attack-on-zero-total-stake-ottersec-none-thala-lsd-deps-pdf

Semantic anchor:
  `staking::stake_thAPT_v2` lets the first depositor distort the
  thAPT:stAPT exchange rate when share minting divides by `total_stake`
  before any zero-total-stake bootstrap path is enforced.

Detection strategy:
  Flag Move staking_v2 functions that mint shares through an
  `amount * total_shares / total_stake`-style ratio without a local
  `total_stake == 0` bootstrap guard, fixed initial-share branch, or
  minimum-deposit seeding mechanism.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_STAKE_V2_FN_RE = re.compile(
    r"\bfun\s+(stake_thapt_v2|stake_v2|deposit_v2)\s*[(<]",
    re.IGNORECASE | re.DOTALL,
)

_SHARE_RATIO_RE = re.compile(
    r"\*\s*[\w.]*(?:total_shares|shares_outstanding|total_supply)[\w.]*\s*/"
    r"\s*[\w.]*(?:total_stake|total_assets|total_locked|reserve)[\w.]*",
    re.IGNORECASE | re.DOTALL,
)

_ZERO_STAKE_BOOTSTRAP_RE = re.compile(
    r"(?:if\s*\(\s*[\w.]*(?:total_stake|total_assets)[\w.]*\s*==\s*0|"
    r"if\s+[\w.]*(?:total_stake|total_assets)[\w.]*\s*==\s*0|"
    r"assert!\s*\(\s*[\w.]*(?:total_stake|total_assets)[\w.]*\s*>\s*0|"
    r"minimum_deposit|initial_shares|INITIAL_SUPPLY|INITIAL_SHARES)",
    re.IGNORECASE,
)

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


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


def _strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def scan_text(source: str, filepath: str = '<memory>') -> list[dict]:
    hits: list[dict] = []
    for m in _STAKE_V2_FN_RE.finditer(source):
        body = _strip_comments(_extract_fn_body(source, m.start()))
        if _SHARE_RATIO_RE.search(body) and not _ZERO_STAKE_BOOTSTRAP_RE.search(body):
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "medium",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` mints staking_v2 shares with a total-stake ratio "
                    "without a zero-total-stake bootstrap guard; first-depositor "
                    "share inflation can depeg the exchange rate."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding='utf-8', errors='replace'), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect: Inflation attack on zero-total-stake staking_v2")
    parser.add_argument('paths', nargs='+', type=Path)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    hits: list[dict] = []
    for p in args.paths:
        if p.is_dir():
            for f in sorted(p.rglob('*.move')):
                hits.extend(scan_file(f))
        elif p.suffix == '.move':
            hits.extend(scan_file(p))
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['filepath']}:{h['line']}: {h['severity']}: {h['message']}")
    return 1 if hits else 0


if __name__ == '__main__':
    raise SystemExit(main())
