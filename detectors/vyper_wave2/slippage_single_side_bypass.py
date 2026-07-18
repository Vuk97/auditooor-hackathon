"""
slippage-minimum-doesn-t-work-during-single-side-redemption.

Bug class: slippage / dex-integration
Language:  vyper
Source:    solodit-2026-04-cycle32-vyper / Sherlock Notional
Source URL: https://solodit.cyfrin.io/issues/h-4-slippageminimum-amount-does-not-work-during-single-side-redemption-sherlock-notional-notional-update-2-git

Semantic anchor:
  `_getMinExitAmounts` / `_get_min_amounts` returns a minimum-amount
  array calculated for PROPORTIONAL withdrawal.  When the redemption
  takes a SINGLE-SIDE path (exit one token only), those minimums are
  ignored or applied incorrectly — the slippage protection is
  effectively bypassed.

Detection strategy:
  Flag Vyper contracts where:
    1. A function calculates minimum exit amounts (min_amounts, slippage,
       _min_exit, …) generically (without branching on the exit-mode).
    2. The same scope contains a single-side or imbalanced exit call
       that does NOT re-derive minimums for the single-asset path.

  Proxy signal: the slippage array is computed before a conditional
  that dispatches to single-side remove_liquidity, but the array is
  passed unchanged to the single-side branch.

M14-trap note:
  The bug class is "slippage protection ignores single-side path" —
  the predicate checks for a mismatch between min-amount derivation
  scope and the exit branch used, not for a fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_SLIPPAGE_COMPUTE_RE = re.compile(
    r"\b(?:_getMinExitAmounts|_get_min_amounts|_compute_slippage|"
    r"min_exit_amounts|min_amounts|slippage_amounts)\b",
    re.IGNORECASE,
)

_SINGLE_SIDE_EXIT_RE = re.compile(
    r"\b(?:remove_liquidity_one_coin|remove_liquidity_imbalance|"
    r"single_side_redeem|single_asset_exit|single_token_exit)\b",
    re.IGNORECASE,
)

# A re-derive of min amounts specifically for the single-side path (the fix)
_SINGLE_SIDE_MIN_RE = re.compile(
    r"\b(?:min_amount_single|single_min|one_coin_min|single_side_min)\b",
    re.IGNORECASE,
)

_FN_RE = re.compile(
    r"def\s+(redeem|withdraw|exit|remove_liquidity|burn_for_tokens)\s*\(",
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
    for m in _FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        has_slippage_compute = bool(_SLIPPAGE_COMPUTE_RE.search(body))
        has_single_exit = bool(_SINGLE_SIDE_EXIT_RE.search(body))
        has_single_min = bool(_SINGLE_SIDE_MIN_RE.search(body))
        if has_slippage_compute and has_single_exit and not has_single_min:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` computes slippage/minimum-exit amounts for a "
                    "proportional path but passes them to a single-side exit call "
                    "without re-deriving the correct single-asset minimum. "
                    "Slippage protection is ineffective on the single-side path."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect slippage bypass on single-side redemption in Vyper."
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
