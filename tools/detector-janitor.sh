#!/usr/bin/env bash
# detector-janitor.sh — R73 A1: auto-demote noisy-and-zero-TP patterns to
# graveyard; auto-retire patterns with no hits across 6+ engagements.
#
# Reads detectors/_hits_ledger.yaml and detectors/_tier_registry.yaml.
# Applies 3 rules:
#
#   Rule 1 — Noisy-zero-TP:
#     ≥20 hits AND 0 TPs AND ≥3 FPs  →  tier D (graveyard)
#
#   Rule 2 — Cold-zero-ratio:
#     ≥50 hits AND ratio < 0.01       →  tier D (graveyard)
#
#   Rule 3 — Unused-across-engagements:
#     0 hits across 6+ engagements   →  tier D (graveyard)
#
# Rationale: R51 tier-backfill promoted 400+ patterns to E without engagement
# evidence. A subset are noisy on real targets (10+ hits / 0 TPs), polluting
# scan output. Cleaning them moves C3 scoped-ratio up and operator-read time
# down.
#
# Usage:
#   bash tools/detector-janitor.sh          # apply demotions (modifies tier_registry)
#   bash tools/detector-janitor.sh --dry-run
#   bash tools/detector-janitor.sh --rule 1 # only apply rule 1
#   bash tools/detector-janitor.sh --revive # print graveyard patterns with recent hits
#
# Idempotent: patterns already in tier D are skipped.
# Auto-runs via flow-gate.sh --strict once per round.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="$AUDITOOOR_DIR/detectors/_hits_ledger.yaml"
REGISTRY="$AUDITOOOR_DIR/detectors/_tier_registry.yaml"

DRY=0
REVIVE=0
RULES="1,2,3"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --revive)  REVIVE=1; shift ;;
    --rule)    RULES="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# //; s/^#//'
      exit 0 ;;
    *) echo "[err] unknown arg: $1" >&2; exit 1 ;;
  esac
done

[ -f "$LEDGER" ]   || { echo "[err] ledger not found: $LEDGER" >&2; exit 1; }
[ -f "$REGISTRY" ] || { echo "[err] tier registry not found: $REGISTRY" >&2; exit 1; }

python3 - "$LEDGER" "$REGISTRY" "$DRY" "$REVIVE" "$RULES" <<'PY'
import sys, yaml, json, copy

ledger_path, registry_path, dry, revive, rules = sys.argv[1:]
dry = int(dry); revive = int(revive); rules = set(rules.split(","))

led = yaml.safe_load(open(ledger_path)) or {}
reg = yaml.safe_load(open(registry_path)) or {}

# Handle both shapes: top-level detectors dict OR {version: N, detectors: {...}}
if isinstance(led, dict) and 'detectors' in led:
    dets = led['detectors']
else:
    dets = led

# Tier-registry shape: top-level {name: {tier: S|E|D, ...}}
if isinstance(reg, dict) and 'detectors' in reg:
    tiers = reg['detectors']
else:
    tiers = reg

demotions = []
promotions_pending = []  # for --revive

for name, det in (dets or {}).items():
    if not isinstance(det, dict):
        continue
    hits = det.get('hits', 0) or 0
    tp = det.get('tp', 0) or 0
    fp = det.get('fp', 0) or 0
    unknown = det.get('unknown', 0) or 0

    # Unique engagement count
    history = det.get('_history', []) or []
    engagements = set()
    for h in history:
        if isinstance(h, dict):
            ws = h.get('workspace', '')
            if ws:
                engagements.add(ws)

    current_tier = None
    if name in tiers and isinstance(tiers[name], dict):
        current_tier = tiers[name].get('tier')

    # --revive: find graveyard patterns that would now re-qualify
    if revive:
        if current_tier == 'D' and tp > 0:
            promotions_pending.append((name, tp, fp, hits))
        continue

    # Already in D → skip
    if current_tier == 'D':
        continue

    reasons = []
    # Rule 1: noisy-zero-TP
    if "1" in rules and hits >= 20 and tp == 0 and fp >= 3:
        reasons.append(f"rule-1 (≥20 hits, 0 TPs, ≥{fp} FPs)")

    # Rule 2: cold-zero-ratio
    if "2" in rules and hits >= 50:
        ratio = tp / max(hits, 1)
        if ratio < 0.01:
            reasons.append(f"rule-2 (≥50 hits, ratio={ratio:.3f})")

    # Rule 3: unused across engagements
    if "3" in rules and hits == 0 and len(engagements) == 0:
        # Further gate: detector must have existed for ≥6 rounds. Approx via
        # count of distinct rounds seen in tier-registry metadata — absent
        # that, skip Rule 3 to avoid false demotions of fresh patterns.
        first_seen = (tiers.get(name, {}) if isinstance(tiers, dict) else {}).get('first_round')
        if first_seen and isinstance(first_seen, (int, str)):
            try:
                fs = int(str(first_seen).lstrip('R'))
                CURRENT_ROUND = 73
                if CURRENT_ROUND - fs >= 6:
                    reasons.append(f"rule-3 (unused since R{fs}, ≥6 rounds old, 0 engagements)")
            except Exception:
                pass

    if reasons:
        demotions.append((name, current_tier, reasons, hits, tp, fp))

if revive:
    print("=== Graveyard patterns with ≥1 TP (candidates for revival) ===")
    if not promotions_pending:
        print("  (none)")
    else:
        for name, tp, fp, hits in sorted(promotions_pending, key=lambda x: -x[1]):
            print(f"  {name}: tp={tp}, fp={fp}, hits={hits}")
    sys.exit(0)

print(f"=== detector-janitor report ===")
print(f"  Ledger dets      : {len(dets or {})}")
print(f"  Registry entries : {len(tiers or {})}")
print(f"  Rules applied    : {sorted(rules)}")
print(f"  Demotion candidates: {len(demotions)}")
print()

if not demotions:
    print("  No patterns meet demotion criteria. Library is healthy.")
    sys.exit(0)

for name, cur, reasons, hits, tp, fp in demotions:
    print(f"  [{cur or '?'} → D] {name}")
    for r in reasons:
        print(f"    · {r}")
    print(f"    hits={hits} tp={tp} fp={fp}")

if dry:
    print()
    print("  [dry-run] no changes written.")
    sys.exit(0)

# Apply demotions to tier registry
changed = 0
for name, _cur, _reasons, _h, _t, _f in demotions:
    if name not in tiers:
        tiers[name] = {'tier': 'D', 'auto_demoted': True, 'reason': _reasons}
    else:
        tiers[name]['tier'] = 'D'
        tiers[name]['auto_demoted'] = True
        tiers[name]['demote_reason'] = _reasons
    changed += 1

# Write back — preserve top-level structure
if isinstance(reg, dict) and 'detectors' in reg:
    reg['detectors'] = tiers
    out = reg
else:
    out = tiers

yaml.safe_dump(out, open(registry_path, 'w'), sort_keys=False, default_flow_style=False)
print(f"\n  [ok] demoted {changed} pattern(s) to tier D in {registry_path}")
print(f"  Run `bash tools/detector-janitor.sh --revive` to see graveyard patterns that could be re-promoted.")
PY
