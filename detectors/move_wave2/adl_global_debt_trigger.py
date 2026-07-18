"""
adl-triggers-on-global-debt-instead-of-per-group-liquidates-healthy.

Bug class: liquidation / accounting scope
Language:  move (Sui)
Source:    solodit-2026-04-cycle20-move / Sherlock CurrentSUI
Source URL: https://solodit.cyfrin.io/issues/m-3-adl-borrow-deleverage-triggers-on-global-debt-instead-of-per-group-debt-force-liquidating-healthy-positions-sherlock-currentsui-contest-march-2026-git

Semantic anchor:
  The auto-deleverage (ADL) trigger checks `global_debt` instead of the
  `per_group_debt` for the specific collateral group.  Healthy positions
  in one group are force-liquidated because an unrelated group's debt
  pushed the global metric over threshold.

Detection strategy:
  Flag Move ADL / deleverage functions where:
    1. The trigger condition references a GLOBAL debt variable
       (total_debt, global_debt, protocol_debt, …).
    2. The function operates on a specific collateral group / coin type
       (has a group_id / coin_type parameter).
    3. There is no per-group debt lookup used in the trigger condition.

  Proxy signal: trigger uses `total_debt` or `global_debt` rather than
  `group.debt` or `get_group_debt(group_id)`.

M14-trap note:
  Bug class is "wrong scope for ADL trigger — global vs per-group debt" —
  predicate checks the scope of the debt variable, not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_ADL_FN_RE = re.compile(
    r"fun\s+(trigger_adl|auto_deleverage|adl_borrow|deleverage|"
    r"force_liquidate|liquidate_position)\s*[(<]",
    re.IGNORECASE,
)

# Global debt reference (wrong scope)
_GLOBAL_DEBT_RE = re.compile(
    r"\b(?:total_debt|global_debt|protocol_debt|total_borrow|"
    r"global_borrow)\b",
    re.IGNORECASE,
)

# Per-group debt reference (correct scope)
_GROUP_DEBT_RE = re.compile(
    r"\b(?:group(?:_debt|\.debt)|per_group_debt|group_id.*debt|"
    r"get_group_debt|group_borrow|segment_debt)\b",
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


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _ADL_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        has_global = bool(_GLOBAL_DEBT_RE.search(body))
        has_per_group = bool(_GROUP_DEBT_RE.search(body))
        if has_global and not has_per_group:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "medium",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` triggers auto-deleverage using global debt "
                    "(`total_debt`/`global_debt`) instead of per-group debt. "
                    "Healthy positions in a collateral group may be force-liquidated "
                    "due to unrelated debt in another group."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect global-debt ADL trigger that should use per-group debt in Move."
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
