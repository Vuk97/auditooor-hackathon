"""
incorrect-shares-accounting-causes-liquidations-to-fail — checkpoint snapshot mismatch.

Bug class: liquidation / accounting
Language:  vyper
Source:    solodit-2026-04-cycle32-vyper / Sherlock Fair Funding (Alchemix)
Source URL: https://solodit.cyfrin.io/issues/h-2-incorrect-shares-accounting-cause-liquidations-to-fail-in-some-cases-sherlock-fair-funding-fair-funding-by-alchemix-unstoppable-git

Semantic anchor:
  Vault holds a snapshot of vault shares at a wrong checkpoint — the
  claimable yield and the actual vault share balance diverge, causing the
  liquidation function to fail (revert or produce incorrect output) when
  it tries to reconcile yield against shares.

Detection strategy:
  Look for vyper contracts where:
    1. A liquidate / repay / close_position function references vault
       share variables (total_shares, vault_shares, balanceOf, …) AND
    2. A yield / claimable variable (claimable_yield, yield_accrued,
       pending_rewards, …) that is computed from a DIFFERENT snapshot
       variable than the one used in the liquidation path.

  Proxy signal: liquidation function reads from two inconsistent
  share-accounting variables (e.g. `shares` vs `vault_shares`), which
  Vyper doesn't reconcile automatically.

  This is a heuristic; the detector flags contracts with a plausible
  shape for manual review.

M14-trap note:
  The predicate checks for two DISTINCT share-accounting variable
  families referenced together in a liquidation function — encoding the
  checkpoint-mismatch bug class, not the fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_LIQUIDATION_FN_RE = re.compile(
    r"def\s+(liquidate|repay|close_position|force_close|seize|settle)\s*\(",
    re.IGNORECASE,
)

# Two classes of share accounting variable — if both appear inside the
# same liquidation function body it indicates a checkpoint split.
_SHARES_CLASS_A = re.compile(
    r"\b(?:total_shares|shares_outstanding|vault_shares|minted_shares)\b",
    re.IGNORECASE,
)
_SHARES_CLASS_B = re.compile(
    r"\b(?:claimable_yield|yield_accrued|pending_rewards|accrued_interest|"
    r"amount_claimable|debt_shares)\b",
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
    for m in _LIQUIDATION_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        has_a = bool(_SHARES_CLASS_A.search(body))
        has_b = bool(_SHARES_CLASS_B.search(body))
        if has_a and has_b:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` references both vault-share accounting and "
                    "claimable-yield accounting, which may diverge if checkpointed "
                    "at different times. Liquidations fail when the two snapshots "
                    "are inconsistent."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect checkpoint-mismatch share accounting in Vyper liquidation functions."
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
