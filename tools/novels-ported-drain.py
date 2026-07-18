#!/usr/bin/env python3
"""novels-ported-drain.py - report the DETECTOR-class unported drain.

Reads the owned ledger audit/corpus_tags/novels_ported_ledger.yaml and reports
the before/after unported count for the DETECTOR-class novels enumerated in
reference/corpus_mined/NOVELS_UNPORTED.md ("Full DETECTOR novel list (46)").

  unported_before = detector_universe - count(ported_before_this_lane == true)
  unported_after  = detector_universe - count(all ported entries)
  drop            = unported_before - unported_after
                  = count(ported this lane)

This is a mechanical accounting tool; it asserts nothing about impact. It exists
so a lane that ports N novels can PROVE the unported count fell by exactly N,
without editing NOVELS_UNPORTED.md (prose) or the other lane's inventory tool.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "audit" / "corpus_tags" / "novels_ported_ledger.yaml"
SCHEMA_VERSION = "auditooor.novels_ported_drain.v1"


def load_ledger(path: Path = LEDGER_PATH) -> Dict[str, Any]:
    import yaml  # type: ignore

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("ledger is not a mapping")
    return data


def compute_drain(ledger: Dict[str, Any]) -> Dict[str, Any]:
    universe = int(ledger.get("detector_universe") or 0)
    ported: List[Dict[str, Any]] = [
        e for e in (ledger.get("ported") or []) if isinstance(e, dict)
    ]
    before = [e for e in ported if bool(e.get("ported_before_this_lane"))]
    this_lane = [e for e in ported if not bool(e.get("ported_before_this_lane"))]
    unported_before = universe - len(before)
    unported_after = universe - len(ported)
    return {
        "schema_version": SCHEMA_VERSION,
        "detector_universe": universe,
        "ported_before_this_lane": len(before),
        "ported_this_lane": len(this_lane),
        "ported_total": len(ported),
        "unported_before": unported_before,
        "unported_after": unported_after,
        "drop": unported_before - unported_after,
        "this_lane_novels": [
            {"novel_id": e.get("novel_id"), "name": e.get("name"), "kind": e.get("kind")}
            for e in this_lane
        ],
    }


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args(argv)
    report = compute_drain(load_ledger(args.ledger))
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"DETECTOR-class novel universe : {report['detector_universe']}")
    print(f"ported before this lane       : {report['ported_before_this_lane']}")
    print(f"ported this lane              : {report['ported_this_lane']}")
    print(
        f"unported: {report['unported_before']} -> {report['unported_after']} "
        f"(drop {report['drop']})"
    )
    for n in report["this_lane_novels"]:
        print(f"  + #{n['novel_id']} {n['name']} ({n['kind']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
