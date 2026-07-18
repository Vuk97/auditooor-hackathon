#!/usr/bin/env python3
"""registry-orphan-cleanup.py — archive stale registry rows whose .py file no longer exists.

For every Tier-S/A/B row in `detectors/_tier_registry.yaml` that has no on-disk
.py file (as reported by registry-disk-consistency-check), downgrade it to
`tier: ARCHIVED` — a pseudo-tier that:
  - is NOT counted in Tier-S/A/B master-mandate totals
  - preserves full audit trail of what existed
  - carries three extra fields:
      archived_since:       <ISO8601 UTC>
      archived_reason:      <human-readable text>
      tier_before_archived: <original tier>

The tool is idempotent: re-running on the same disk state produces no diffs.

Sources consulted (in order):
  1. --drift-json: output of registry-disk-consistency-check --json-out (preferred)
  2. --tier-d-revival: tier_d_revival_summary.json from /tmp/auditooor-inventory/
  3. Live disk scan (fallback, always runs unless --no-live-scan)

Exit codes:
  0  — success (dry-run printed plan, or apply completed)
  1  — nothing to do (no orphans found)
  2  — error (registry not found, YAML parse error, etc.)

Usage:
  python3 tools/registry-orphan-cleanup.py --dry-run
  python3 tools/registry-orphan-cleanup.py --apply
  python3 tools/registry-orphan-cleanup.py --apply --drift-json /tmp/_registry_drift.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
HIGH_TIERS = {"S", "A", "B"}
ARCHIVED_TIER = "ARCHIVED"

DEFAULT_DRIFT_JSON = Path("/tmp/_registry_drift.json")
DEFAULT_REVIVAL_JSON = Path("/private/tmp/auditooor-inventory/tier_d_revival_summary.json")


# ---------------------------------------------------------------------------
# Helper: find .py for an argument (mirrors registry-disk-consistency-check)
# ---------------------------------------------------------------------------

def find_py_for_argument(arg: str) -> Path | None:
    """Return detector .py path if it exists on disk, else None."""
    snake = arg.replace("-", "_")
    # Fast path: filename matches snake form
    for wave_dir in (REPO / "detectors").glob("wave*"):
        if not wave_dir.is_dir():
            continue
        candidate = wave_dir / f"{snake}.py"
        if candidate.exists():
            return candidate
    # Also check rust_wave* etc.
    for wave_dir in (REPO / "detectors").iterdir():
        if not wave_dir.is_dir() or wave_dir.name.startswith("_"):
            continue
        candidate = wave_dir / f"{snake}.py"
        if candidate.exists():
            return candidate
    # Slow path: grep ARGUMENT = "..." inside any .py
    pattern = re.compile(
        rf'^\s*ARGUMENT\s*=\s*[\'"]{re.escape(arg)}[\'"]', re.MULTILINE
    )
    for p in (REPO / "detectors").glob("**/*.py"):
        if p.name.startswith("_"):
            continue
        try:
            if pattern.search(p.read_text(encoding="utf-8", errors="replace")):
                return p
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Collect orphan argument names from multiple sources
# ---------------------------------------------------------------------------

def orphans_from_drift_json(path: Path) -> set[str]:
    """Parse registry-disk-consistency-check --json-out output."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        print(f"[warn] could not parse drift JSON {path}: {exc}", file=sys.stderr)
        return set()
    drift_rows = data.get("drift_rows", [])
    return {
        r["argument"]
        for r in drift_rows
        if any("no .py file" in p for p in r.get("problems", []))
    }


def orphans_from_revival_json(path: Path) -> set[str]:
    """Parse tier_d_revival_summary.json — 'unrevivable' bucket may be a list."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        print(f"[warn] could not parse revival JSON {path}: {exc}", file=sys.stderr)
        return set()
    bucket = data.get("buckets", {}).get("unrevivable", [])
    if isinstance(bucket, list):
        return set(bucket)
    # If it's an int/count, we can't extract names — skip
    return set()


def orphans_from_live_scan(tiers: dict) -> set[str]:
    """Walk the registry; for every high-tier row with no .py, flag it."""
    result = set()
    for arg, row in tiers.items():
        tier = row.get("tier", "")
        if tier not in HIGH_TIERS:
            continue
        if find_py_for_argument(arg) is None:
            result.add(arg)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Archive stale registry rows whose .py file no longer exists."
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true",
                      help="Print what would be archived; do not modify the registry.")
    mode.add_argument("--apply", action="store_true",
                      help="Apply changes to _tier_registry.yaml in-place.")
    ap.add_argument("--drift-json", type=Path, default=DEFAULT_DRIFT_JSON,
                    help=f"Path to registry-disk-consistency-check JSON output "
                         f"(default: {DEFAULT_DRIFT_JSON}).")
    ap.add_argument("--revival-json", type=Path, default=DEFAULT_REVIVAL_JSON,
                    help=f"Path to tier_d_revival_summary.json "
                         f"(default: {DEFAULT_REVIVAL_JSON}).")
    ap.add_argument("--no-live-scan", action="store_true",
                    help="Skip live disk scan (rely only on --drift-json / --revival-json).")
    ap.add_argument("--archived-reason", default="registry-orphan-cleanup: no .py file on disk",
                    help="Reason string to store in archived_reason.")
    args = ap.parse_args()

    if not TIER_REGISTRY.exists():
        print(f"[error] registry not found: {TIER_REGISTRY}", file=sys.stderr)
        return 2

    # Load YAML preserving order (Python 3.7+ dict is ordered)
    raw_text = TIER_REGISTRY.read_text(encoding="utf-8")
    try:
        reg = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        print(f"[error] YAML parse error: {exc}", file=sys.stderr)
        return 2

    tiers: dict = reg.get("tiers", {}) or {}

    # Gather orphan set from all sources
    orphans: set[str] = set()
    orphans |= orphans_from_drift_json(args.drift_json)
    orphans |= orphans_from_revival_json(args.revival_json)
    if not args.no_live_scan:
        live = orphans_from_live_scan(tiers)
        orphans |= live

    # Intersect with actually-present high-tier registry keys
    # (keys in registry may be snake or kebab; normalize both)
    def registry_key_for(arg: str) -> str | None:
        if arg in tiers and tiers[arg].get("tier") in HIGH_TIERS:
            return arg
        kebab = arg.replace("_", "-")
        if kebab in tiers and tiers[kebab].get("tier") in HIGH_TIERS:
            return kebab
        snake = arg.replace("-", "_")
        if snake in tiers and tiers[snake].get("tier") in HIGH_TIERS:
            return snake
        return None

    candidates: list[tuple[str, dict]] = []  # (registry_key, row)
    for arg in sorted(orphans):
        key = registry_key_for(arg)
        if key is None:
            continue  # already archived or not a high-tier row
        candidates.append((key, tiers[key]))

    if not candidates:
        print("[registry-orphan-cleanup] nothing to archive — registry is clean.")
        return 1

    # Deduplicate (registry_key is canonical)
    seen_keys: set[str] = set()
    unique_candidates: list[tuple[str, dict]] = []
    for key, row in candidates:
        if key not in seen_keys:
            seen_keys.add(key)
            unique_candidates.append((key, row))
    candidates = unique_candidates

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tier_counter: Counter = Counter()

    print(f"[registry-orphan-cleanup] orphans to archive: {len(candidates)}")
    for key, row in candidates:
        prior = row["tier"]
        tier_counter[prior] += 1
        print(f"  [{prior}] {key}")

    print()
    print("Breakdown by tier_before_archived:")
    for tier, count in sorted(tier_counter.items()):
        print(f"  {tier}: {count}")

    if args.dry_run:
        print()
        print("[dry-run] no changes written. Re-run with --apply to commit.")
        return 0

    # --- Apply ---
    for key, row in candidates:
        prior_tier = row["tier"]
        row["tier"] = ARCHIVED_TIER
        row["tier_before_archived"] = prior_tier
        row["archived_since"] = now_iso
        row["archived_reason"] = args.archived_reason
        tiers[key] = row

    # Write back — use yaml.dump with sensible settings
    out = yaml.dump(
        reg,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )
    TIER_REGISTRY.write_text(out, encoding="utf-8")
    print(f"\n[registry-orphan-cleanup] applied — {len(candidates)} rows archived in {TIER_REGISTRY}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
