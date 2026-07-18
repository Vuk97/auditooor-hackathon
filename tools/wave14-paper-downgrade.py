#!/usr/bin/env python3
"""wave14-paper-downgrade.py — downgrade wave14 placeholder detectors to PAPER.

Reads /private/tmp/auditooor-inventory/wave14_triage.json and downgrades only
the rows whose `bucket == "placeholder"` to `tier: PAPER` in the tier registry.

Idempotent + safe:
  - Only touches arguments triaged as `placeholder`.
  - If the row already has `tier: PAPER`, it is skipped.
  - If the row is not in the registry, it is ADDED (wave14 detectors are
    auto-mined and not pre-registered).
  - Records `tier_before_paper`, `paper_since`, `paper_reason`.
  - Default is --dry-run (writes nothing); operator must pass --apply.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
DEFAULT_TRIAGE = Path("/private/tmp/auditooor-inventory/wave14_triage.json")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", default=str(DEFAULT_TRIAGE))
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Actually write the registry. Default is dry-run.",
    )
    ap.add_argument(
        "--summary-out",
        default="/private/tmp/auditooor-inventory/wave14_paper_downgrade_summary.json",
    )
    args = ap.parse_args()

    triage = json.loads(Path(args.triage).read_text(encoding="utf-8"))
    placeholders = [d for d in triage.get("detectors", [])
                    if d.get("bucket") == "placeholder"]

    reg = yaml.safe_load(TIER_REGISTRY.read_text(encoding="utf-8")) or {}
    tiers = reg.setdefault("tiers", {})

    iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    today = iso_now[:10]

    actions: list[dict] = []
    skipped_already_paper: list[str] = []
    added_new_rows: list[str] = []
    downgraded_existing: list[str] = []

    for d in placeholders:
        arg = d["argument"]
        row = tiers.get(arg)
        if row is None:
            actions.append({
                "argument": arg, "action": "add_paper_row",
                "reasons": d.get("reasons", []),
            })
            added_new_rows.append(arg)
            if args.apply:
                tiers[arg] = {
                    "tier": "PAPER",
                    "reason": "wave14-triage placeholder predicates: "
                              + ",".join(d.get("reasons", [])),
                    "waves": [triage.get("wave", "wave14")],
                    "first_added": today,
                    "paper_since": iso_now,
                    "paper_reason":
                        f"wave14-paper-downgrade: placeholder at {today}",
                }
            continue
        cur_tier = row.get("tier")
        if cur_tier == "PAPER":
            skipped_already_paper.append(arg)
            actions.append({"argument": arg, "action": "skip_already_paper"})
            continue
        actions.append({
            "argument": arg, "action": "downgrade_to_paper",
            "tier_before": cur_tier, "reasons": d.get("reasons", []),
        })
        downgraded_existing.append(arg)
        if args.apply:
            row["tier_before_paper"] = cur_tier
            row["tier"] = "PAPER"
            row["paper_since"] = iso_now
            row["paper_reason"] = (
                f"wave14-paper-downgrade: placeholder at {today}"
            )

    if args.apply and (added_new_rows or downgraded_existing):
        tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
        tmp.write_text(
            yaml.safe_dump(reg, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        tmp.replace(TIER_REGISTRY)

    summary = {
        "schema": "auditooor.wave14_paper_downgrade.v1",
        "ran_at": iso_now,
        "applied": bool(args.apply),
        "placeholder_count": len(placeholders),
        "added_new_rows": len(added_new_rows),
        "downgraded_existing": len(downgraded_existing),
        "skipped_already_paper": len(skipped_already_paper),
        "actions": actions,
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))
    print(f"[wave14-paper-downgrade] applied={args.apply}")
    print(f"  placeholders in triage:  {len(placeholders)}")
    print(f"  add_new_paper_rows:      {len(added_new_rows)}")
    print(f"  downgrade_existing:      {len(downgraded_existing)}")
    print(f"  skip_already_paper:      {len(skipped_already_paper)}")
    print(f"  summary -> {args.summary_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
