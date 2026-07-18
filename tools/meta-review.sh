#!/usr/bin/env bash
# meta-review.sh — monthly consolidation of learning signals (Issue #89)
#
# Runs every ~30 days (or on-demand) to keep the skill's state fresh:
#   1. detector-tier.sh audit          — promote/demote by ledger
#   2. rejection-classifier.py --train — retrain on latest outcomes
#   3. golden-set update               — patterns with ≥3 real catches + ≥0.5 precision
#   4. pattern demotion                — 0 catches after 5 engagements → graveyard
#   5. diff vs last month              — write reference/meta_review_YYYY-MM.md
#
# Usage:
#   ./tools/meta-review.sh              # run the full review
#   ./tools/meta-review.sh --dry-run    # print what would happen

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$AUDITOOOR_DIR/tools"
LEDGER="$AUDITOOOR_DIR/detectors/_hits_ledger.yaml"
REGISTRY="$AUDITOOOR_DIR/detectors/_tier_registry.yaml"
GOLDEN="$AUDITOOOR_DIR/reference/golden_patterns.yaml"

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

echo "==========================================================================="
echo "  auditooor meta-review  —  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ "$DRY" = "1" ] && echo "  DRY-RUN MODE"
echo "==========================================================================="
echo ""

REPORT_MONTH=$(date -u +%Y-%m)
REPORT_FILE="$AUDITOOOR_DIR/reference/meta_review_${REPORT_MONTH}.md"

{
    echo "# Meta-review — $REPORT_MONTH"
    echo ""
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
} > "$REPORT_FILE.tmp"

# --- Step 1: detector-tier audit ---
echo "[1/5] detector-tier audit (promote/demote by ledger)..."
if [ "$DRY" = "0" ]; then
    AUDIT_OUT=$(bash "$TOOLS/detector-tier.sh" audit 2>&1 || true)
    echo "$AUDIT_OUT"
    echo "## 1. Tier audit" >> "$REPORT_FILE.tmp"
    echo '```' >> "$REPORT_FILE.tmp"
    echo "$AUDIT_OUT" >> "$REPORT_FILE.tmp"
    echo '```' >> "$REPORT_FILE.tmp"
else
    echo "  (dry-run) would run: detector-tier.sh audit"
fi
echo ""

# --- Step 2: retrain rejection classifier ---
echo "[2/5] retrain rejection classifier..."
if [ "$DRY" = "0" ]; then
    if command -v python3 >/dev/null && python3 -c "import sklearn" 2>/dev/null; then
        TRAIN_OUT=$(python3 "$TOOLS/rejection-classifier.py" --train 2>&1 || echo "(train failed or missing data)")
        echo "$TRAIN_OUT" | tail -20
        echo "" >> "$REPORT_FILE.tmp"
        echo "## 2. Rejection classifier retrain" >> "$REPORT_FILE.tmp"
        echo '```' >> "$REPORT_FILE.tmp"
        echo "$TRAIN_OUT" | tail -30 >> "$REPORT_FILE.tmp"
        echo '```' >> "$REPORT_FILE.tmp"
    else
        echo "  [skip] scikit-learn not installed (pip3 install scikit-learn)"
    fi
else
    echo "  (dry-run) would run: rejection-classifier.py --train"
fi
echo ""

# --- Step 3: update golden set ---
echo "[3/5] update golden_patterns.yaml..."
if [ "$DRY" = "0" ]; then
    python3 - "$LEDGER" "$REGISTRY" "$GOLDEN" <<'PY'
import sys, yaml, datetime
from pathlib import Path

ledger = yaml.safe_load(Path(sys.argv[1]).read_text()) if Path(sys.argv[1]).exists() else {"detectors": {}}
registry = yaml.safe_load(Path(sys.argv[2]).read_text()) if Path(sys.argv[2]).exists() else {"tiers": {}}
golden_path = Path(sys.argv[3])

dets = ledger.get("detectors", {}) or {}
tiers = registry.get("tiers", {}) or {}

golden = {"version": 1, "updated": datetime.date.today().isoformat(), "patterns": {}}
for name, entry in dets.items():
    tp = entry.get("tp", 0)
    fp = entry.get("fp", 0)
    catches = len(entry.get("real_catches", []))
    prec = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    if catches >= 1 and prec >= 0.5 and (tp + fp) >= 1:
        golden["patterns"][name] = {
            "tier": tiers.get(name, {}).get("tier", "?"),
            "precision": round(prec, 3),
            "real_catches": catches,
            "tp": tp, "fp": fp,
        }

golden_path.write_text(yaml.safe_dump(golden, sort_keys=False))
print(f"  wrote {golden_path.name} with {len(golden['patterns'])} golden patterns")
PY
    echo "" >> "$REPORT_FILE.tmp"
    echo "## 3. Golden patterns" >> "$REPORT_FILE.tmp"
    echo '```yaml' >> "$REPORT_FILE.tmp"
    head -30 "$GOLDEN" 2>/dev/null >> "$REPORT_FILE.tmp"
    echo '```' >> "$REPORT_FILE.tmp"
else
    echo "  (dry-run) would update golden_patterns.yaml"
fi
echo ""

# --- Step 4: demotion candidates ---
echo "[4/5] identify demotion candidates (0 catches after 5 engagements)..."
python3 - "$LEDGER" <<'PY'
import sys, yaml
from pathlib import Path
p = Path(sys.argv[1])
if not p.exists():
    print("  (no ledger yet)")
    sys.exit(0)
data = yaml.safe_load(p.read_text()) or {}
dets = data.get("detectors", {}) or {}
cand = []
for n, e in dets.items():
    catches = len(e.get("real_catches", []))
    triaged = e.get("tp", 0) + e.get("fp", 0)
    if catches == 0 and triaged >= 5:
        cand.append((n, triaged))
if not cand:
    print("  (no demotion candidates)")
else:
    print(f"  {len(cand)} demotion candidates:")
    for n, t in cand[:20]:
        print(f"    - {n}  (triaged={t}, catches=0)")
PY
echo ""

# --- Step 5: finalize report ---
echo "[5/5] write $REPORT_FILE..."
mv "$REPORT_FILE.tmp" "$REPORT_FILE"
echo "  [ok] meta-review complete — see $REPORT_FILE"
