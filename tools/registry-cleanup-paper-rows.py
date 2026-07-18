#!/usr/bin/env python3
"""registry-cleanup-paper-rows.py — downgrade unverified Tier-A/B/S rows to PAPER.

T-01 (registry-disk-consistency-check) flags rows that claim Tier-A/B/S but
lack `verified: true` + on-disk artifacts. This script downgrades those rows
to a new `tier: PAPER` (semantic: "registry placeholder, no backing
artifact yet"). PAPER rows are NOT counted toward master-mandate Tier-S/A/B
totals.

Safety:
  - Never touches rows with `verified: true`.
  - Never touches Tier-D / Tier-E / unrated rows.
  - Adds a `paper_since: <ISO8601>` field for audit trail.
  - Records the prior tier as `tier_before_paper`.

Idempotent: re-running with the same artifact state produces no diffs after
the first run.

Usage:
  python3 tools/registry-cleanup-paper-rows.py \\
    [--dry-run] \\
    [--summary-out report.json]
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
HIGH_TIERS = {"S", "A", "B"}


def find_py_for_argument(arg: str) -> Path | None:
    snake = arg.replace("-", "_")
    for wave_dir in (REPO / "detectors").glob("wave*"):
        if not wave_dir.is_dir():
            continue
        candidate = wave_dir / f"{snake}.py"
        if candidate.exists():
            return candidate
    return None


def find_fixtures(arg: str) -> tuple[Path | None, Path | None]:
    snake = arg.replace("-", "_")
    candidates_v = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_vulnerable.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vulnerable.sol",
    ]
    candidates_c = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_clean.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_clean.sol",
    ]
    return (
        next((p for p in candidates_v if p.exists()), None),
        next((p for p in candidates_c if p.exists()), None),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--summary-out", default="/private/tmp/registry_cleanup_summary.json")
    args = ap.parse_args()

    reg = yaml.safe_load(TIER_REGISTRY.read_text(encoding="utf-8"))
    tiers = reg.setdefault("tiers", {})

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    downgraded: list[dict] = []
    kept: list[dict] = []

    for arg, row in tiers.items():
        tier = row.get("tier", "")
        if tier not in HIGH_TIERS:
            continue
        if row.get("verified") is True:
            kept.append({"argument": arg, "tier": tier, "reason": "verified=true"})
            continue
        py_path = find_py_for_argument(arg)
        vuln, clean = find_fixtures(arg)
        if py_path and vuln and clean:
            kept.append({
                "argument": arg, "tier": tier,
                "reason": "has artifacts but no verified=true (run inventory-bulk-promote)",
            })
            continue
        # Downgrade
        downgraded.append({
            "argument": arg,
            "tier_before": tier,
            "tier_after": "PAPER",
            "missing": [
                "py" if not py_path else None,
                "vuln_fixture" if not vuln else None,
                "clean_fixture" if not clean else None,
            ],
        })
        if not args.dry_run:
            row["tier_before_paper"] = tier
            row["tier"] = "PAPER"
            row["paper_since"] = iso_now
            row["paper_reason"] = "registry-cleanup: missing on-disk artifacts at " + today

    if not args.dry_run and downgraded:
        tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.safe_dump(reg, default_flow_style=False, sort_keys=False), encoding="utf-8")
        tmp.replace(TIER_REGISTRY)

    summary = {
        "schema": "auditooor.registry_cleanup_paper.v1",
        "ran_at": iso_now,
        "dry_run": args.dry_run,
        "downgraded_count": len(downgraded),
        "kept_count": len(kept),
        "downgraded": downgraded,
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))
    print(f"[cleanup-paper] dry_run={args.dry_run}")
    print(f"  downgraded to PAPER:  {len(downgraded)}")
    print(f"  kept (verified or has artifacts): {len(kept)}")
    print(f"  summary -> {args.summary_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
