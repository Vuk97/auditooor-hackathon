#!/usr/bin/env python3
"""backfill-tier-registry.py — assign explicit tiers to every detector.

Before this pass the registry listed ~169 detectors explicitly and the rest
defaulted to Tier-D — which meant the `--tier S,E` filter in c3-compute.sh and
scan.sh hid ~248 patterns that had fixtures or real catches.

Universe of detectors = union of:
  - registry keys (detectors/_tier_registry.yaml)
  - ledger keys (detectors/_hits_ledger.yaml)
  - pattern DSL filenames (reference/patterns.dsl/*.yaml)

For each detector not already in the registry, apply these promotion rules in
order (first match wins):

  1. ledger precision >= 0.5 AND triaged >= 3  -> Tier-S
  2. has fixture pair AND precision >= 0.2     -> Tier-E
  3. has fixture pair AND precision < 0.2      -> Tier-D (quarantine)
  4. auto-mined (dh-/glider- prefix) AND prec <= 0.5 -> Tier-D (auto-mined noise)
  5. no fixtures                               -> Tier-D (no fixture)

Precision is read from _hits_ledger.yaml; fixture presence is detected via
  - pattern DSL `fixtures:` block, OR
  - a matching pair under patterns/fixtures/<name>_vuln.sol + _clean.sol.

Writes the updated registry back to detectors/_tier_registry.yaml and also
drops a JSON sidecar at /tmp/r51_agents/tier_backfill_changes.json.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[error] PyYAML required. pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "detectors" / "_tier_registry.yaml"
LEDGER = ROOT / "detectors" / "_hits_ledger.yaml"
PATTERN_DSL = ROOT / "reference" / "patterns.dsl"
FIXTURE_DIR = ROOT / "patterns" / "fixtures"
OUT_JSON = Path("/tmp/r51_agents/tier_backfill_changes.json")


def load_yaml(p: Path) -> dict:
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text()) or {}
    return data


def collect_pattern_names() -> dict[str, dict]:
    """Return {pattern_name: {severity, has_fixtures_block, fixture_pair_exists}}."""
    out: dict[str, dict] = {}
    if not PATTERN_DSL.is_dir():
        return out
    for p in sorted(PATTERN_DSL.glob("*.yaml")):
        name = p.stem
        meta = {"severity": None, "has_fixtures_block": False, "description": ""}
        try:
            data = yaml.safe_load(p.read_text()) or {}
            meta["severity"] = data.get("severity")
            meta["has_fixtures_block"] = bool(data.get("fixtures"))
            meta["description"] = (data.get("help") or data.get("wiki_description")
                                   or data.get("wiki_title") or "")[:160]
        except Exception as exc:  # pragma: no cover
            meta["description"] = f"(parse error: {exc})"
        out[name] = meta
    return out


def collect_fixture_pairs() -> set[str]:
    """Return the set of detector names that have both _vuln.sol and _clean.sol."""
    if not FIXTURE_DIR.is_dir():
        return set()
    vuln: set[str] = set()
    clean: set[str] = set()
    for f in FIXTURE_DIR.iterdir():
        if not f.is_file():
            continue
        m_v = re.match(r"^(.*)_vuln\.sol$", f.name)
        m_c = re.match(r"^(.*)_clean\.sol$", f.name)
        if m_v:
            vuln.add(m_v.group(1))
        elif m_c:
            clean.add(m_c.group(1))
    return vuln & clean


def is_auto_mined(name: str) -> bool:
    return name.startswith("dh-") or name.startswith("glider-")


def classify(
    name: str,
    ledger_entry: dict | None,
    pattern_meta: dict | None,
    has_fixture_pair: bool,
) -> tuple[str, str]:
    tp = (ledger_entry or {}).get("tp", 0) or 0
    fp = (ledger_entry or {}).get("fp", 0) or 0
    triaged = tp + fp
    precision = (ledger_entry or {}).get("precision")
    if precision is None:
        precision = (tp / triaged) if triaged else 0.0
    has_fixture = has_fixture_pair or bool((pattern_meta or {}).get("has_fixtures_block"))

    # Rule 1: strong ledger signal -> S
    if triaged >= 3 and precision >= 0.5:
        return (
            "S",
            f"backfill: ledger precision={precision:.2f} over {triaged} triages (auto-promoted by R51 Track A)",
        )

    # Rule 4 (run before fixture rules for quarantined auto-mined patterns):
    if is_auto_mined(name) and (triaged == 0 or precision <= 0.5):
        return (
            "D",
            "backfill: auto-mined noise (dh-/glider- prefix, no strong ledger evidence) — R51 Track A",
        )

    # Rules 2 & 3: fixture-gated
    if has_fixture:
        if precision >= 0.2 or triaged == 0:
            sev = (pattern_meta or {}).get("severity") or "?"
            return (
                "E",
                f"backfill: fixture pair present (severity={sev}), precision={precision:.2f} — R51 Track A",
            )
        return (
            "D",
            f"backfill: quarantined — fixture pair present but precision={precision:.2f} over {triaged} triages — R51 Track A",
        )

    # Rule 5: no fixtures
    return (
        "D",
        "backfill: no fixture pair yet — R51 Track A",
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Assign explicit tiers to every detector. "
                    "Writes detectors/_tier_registry.yaml in place by default; "
                    "use --dry-run to preview without mutating any file.",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help=("Plan only: print the tier assignments that WOULD be written "
              "but do not modify _tier_registry.yaml or the JSON sidecar. "
              "Always exits 0 when the plan succeeds."),
    )
    ap.add_argument(
        "--backup-dir",
        type=Path,
        default=Path("~/.cache/audit-tiers"),
        help=("Directory to snapshot the existing _tier_registry.yaml into "
              "before mutation. Default: ~/.cache/audit-tiers/. Ignored "
              "under --dry-run."),
    )
    return ap.parse_args(argv)


def _snapshot_registry(backup_dir: Path, registry_path: Path) -> Path | None:
    """Copy the current registry to <backup_dir>/backup-<timestamp>.yaml.

    Returns the snapshot path on success, None if the registry is absent
    (nothing to back up). Raises on filesystem errors.
    """
    if not registry_path.exists():
        return None
    backup_dir = backup_dir.expanduser()
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    dest = backup_dir / f"backup-{stamp}.yaml"
    shutil.copy2(registry_path, dest)
    return dest


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    registry = load_yaml(REGISTRY) or {"version": 1, "tiers": {}}
    registry.setdefault("version", 1)
    registry.setdefault("tiers", {})
    tiers = registry["tiers"]

    ledger = load_yaml(LEDGER) or {}
    led_dets = ledger.get("detectors", {}) or {}

    pattern_meta = collect_pattern_names()
    fixture_pairs = collect_fixture_pairs()

    universe = set(tiers.keys()) | set(led_dets.keys()) | set(pattern_meta.keys())
    pre_existing = set(tiers.keys())
    missing = sorted(universe - pre_existing)

    print(f"[backfill] universe size: {len(universe)}")
    print(f"[backfill] already tiered: {len(pre_existing)}")
    print(f"[backfill] un-registered to process: {len(missing)}")
    print(f"[backfill] pattern DSL files: {len(pattern_meta)}")
    print(f"[backfill] fixture pairs on disk: {len(fixture_pairs)}")

    today = datetime.date.today().isoformat()
    promotions: list[dict] = []
    demotions: list[dict] = []
    counts = {"S": 0, "E": 0, "D": 0}

    for name in missing:
        ledger_entry = led_dets.get(name)
        pmeta = pattern_meta.get(name)
        has_pair = name in fixture_pairs
        tier, reason = classify(name, ledger_entry, pmeta, has_pair)
        counts[tier] += 1

        entry = {
            "tier": tier,
            "reason": reason,
            "first_added": today,
            "last_promoted": today,
        }
        if pmeta and pmeta.get("severity"):
            entry["severity_class"] = pmeta["severity"]
        if has_pair or (pmeta and pmeta.get("has_fixtures_block")):
            entry["fixture_pair"] = f"patterns/fixtures/{name}"
        tiers[name] = entry

        record = {
            "name": name,
            "tier": tier,
            "reason": reason,
            "precision": (ledger_entry or {}).get("precision"),
            "triaged": ((ledger_entry or {}).get("tp", 0) + (ledger_entry or {}).get("fp", 0)) if ledger_entry else 0,
            "has_fixture": has_pair or bool((pmeta or {}).get("has_fixtures_block")),
            "severity": (pmeta or {}).get("severity"),
            "auto_mined": is_auto_mined(name),
        }
        if tier == "S":
            promotions.append(record)
        elif tier == "D":
            demotions.append(record)

    # Sort deliverable lists so top-10s are stable/meaningful.
    promotions.sort(key=lambda r: (-(r["precision"] or 0), -(r["triaged"] or 0), r["name"]))
    demotions.sort(key=lambda r: (r["has_fixture"], r["auto_mined"], r["name"]))

    # Stats summary across whole registry after backfill.
    registry["tiers"] = tiers
    final_counts = {"S": 0, "E": 0, "D": 0}
    for entry in tiers.values():
        final_counts[entry.get("tier", "D")] = final_counts.get(entry.get("tier", "D"), 0) + 1

    print("\n[backfill] per-class counts on newly registered detectors:")
    for t in ("S", "E", "D"):
        print(f"  Tier {t}: {counts[t]}")
    print("\n[backfill] per-class counts across full registry after backfill:")
    for t in ("S", "E", "D"):
        print(f"  Tier {t}: {final_counts[t]}")

    if args.dry_run:
        print("\n[backfill] DRY-RUN: no files written.")
        # Print a compact preview so operators can spot regressions before
        # committing to a real run.
        print(f"[backfill] would write {REGISTRY}")
        print(f"[backfill] would write {OUT_JSON}")
        for r in promotions[:5]:
            print(f"  + S {r['name']}  precision={r['precision']}")
        for r in demotions[:5]:
            print(f"  - D {r['name']}  reason=quarantine")
        return 0

    # Snapshot the existing registry before mutation. This gives operators a
    # rollback point if the run lands a regression — safer than relying on
    # `git stash` while the registry sits next to other staged changes.
    snapshot = _snapshot_registry(args.backup_dir, REGISTRY)
    if snapshot is not None:
        print(f"[backfill] snapshot saved: {snapshot}")

    # Write registry back out (sort_keys False to preserve human-readable block order).
    REGISTRY.write_text(yaml.safe_dump(registry, sort_keys=False, width=1000))
    print(f"[backfill] wrote {REGISTRY}")

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps({
        "universe": len(universe),
        "pre_existing": len(pre_existing),
        "newly_tiered": len(missing),
        "new_counts": counts,
        "final_counts": final_counts,
        "top_promotions": promotions[:10],
        "top_demotions": demotions[:10],
    }, indent=2, default=str))
    print(f"[backfill] wrote {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
