#!/usr/bin/env bash
# quick-mine.sh — One-command angle investigation pipeline
#
# Takes a CCIA attack angle and produces a complete investigation package:
#   1. Mining brief (focused investigation plan)
#   2. Contract snapshot (one-page contract summary)
#   3. PoC scaffold (Foundry test skeleton)
#   4. Submission draft (complete markdown)
#   5. Variant detector (dupe-risk check)
#   6. Pre-submit check (20-check gate)
#
# Usage:
#   ./tools/quick-mine.sh <workspace> --angle-id A-REENT --contract CTFExchange --func cancelOrder
#   ./tools/quick-mine.sh ~/audits/polymarket --angle-id A-ORACLE --contract UmaCtfAdapter
#
# Output:
#   ~/audits/<ws>/quick_mine/<angle-id>/<contract>/<timestamp>/
#     brief.md, snapshot.md, poc.t.sol, draft.md, variant-report.json

set -uo pipefail

WS="${1:-}"
shift 2>/dev/null || true

ANGLE_ID=""
CONTRACT=""
FUNC=""

while [ $# -gt 0 ]; do
    case "$1" in
        --angle-id) ANGLE_ID="$2"; shift 2 ;;
        --contract) CONTRACT="$2"; shift 2 ;;
        --func) FUNC="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ -z "$WS" ] || [ ! -d "$WS" ]; then
    echo "usage: $0 <workspace> --angle-id <ID> --contract <Name> [--func <name>]"
    exit 1
fi

if [ -z "$ANGLE_ID" ] || [ -z "$CONTRACT" ]; then
    echo "usage: $0 <workspace> --angle-id <ID> --contract <Name> [--func <name>]"
    echo ""
    echo "Available angles (run CCIA first if empty):"
    python3 "$(dirname "$0")/ccia.py" "$WS" --attack-angles 2>/dev/null | grep '"id"' | head -10
    exit 1
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WS_NAME=$(basename "$WS")
TS=$(date +%Y%m%d_%H%M%S)
OUT_DIR="$WS/quick_mine/${ANGLE_ID}_${CONTRACT}_${TS}"
mkdir -p "$OUT_DIR"

echo "==========================================================================="
echo "  Quick Mine — $ANGLE_ID on $CONTRACT${FUNC:+.$FUNC}"
echo "  Workspace: $WS_NAME"
echo "  Output: $OUT_DIR"
echo "==========================================================================="
echo ""

# --- Step 1: Generate mining brief ---
echo "[quick-mine] Step 1/6: Mining brief ..."
python3 "$AUDITOOOR_DIR/tools/mining-brief-generator.py" "$WS" \
    --top 1 --out-dir "$OUT_DIR" 2>&1 | tail -3

# Find the generated brief and copy it with a clean name
BRIEF=$(find "$OUT_DIR" -name "brief_*${ANGLE_ID}*.md" | head -1)
if [ -n "$BRIEF" ]; then
    cp "$BRIEF" "$OUT_DIR/brief.md"
    echo "[quick-mine] Brief: $OUT_DIR/brief.md"
fi

# --- Step 2: Contract snapshot ---
echo ""
echo "[quick-mine] Step 2/6: Contract snapshot ..."
# Find contract source file
SOL_FILE=$(find "$WS/src" -name "${CONTRACT}.sol" 2>/dev/null | head -1)
if [ -z "$SOL_FILE" ]; then
    SOL_FILE=$(find "$WS" -name "${CONTRACT}.sol" -not -path "*/lib/*" 2>/dev/null | head -1)
fi

if [ -n "$SOL_FILE" ]; then
    python3 "$AUDITOOOR_DIR/tools/contract-snapshot.py" "$SOL_FILE" --out "$OUT_DIR/snapshot.md" 2>&1 | tail -3
    echo "[quick-mine] Snapshot: $OUT_DIR/snapshot.md"
else
    echo "[quick-mine] Warning: Could not find ${CONTRACT}.sol"
fi

# --- Step 3: PoC scaffold ---
echo ""
echo "[quick-mine] Step 3/6: PoC scaffold ..."
python3 "$AUDITOOOR_DIR/tools/poc-scaffold.py" \
    --pattern "$ANGLE_ID" --contract "$CONTRACT" ${FUNC:+--func "$FUNC"} \
    --out "$OUT_DIR/poc.t.sol" 2>&1 | tail -5

# --- Step 4: Submission draft ---
echo ""
echo "[quick-mine] Step 4/6: Submission draft ..."
python3 "$AUDITOOOR_DIR/tools/auto-draft-generator.py" "$WS" \
    --angle-id "$ANGLE_ID" --contract "$CONTRACT" ${FUNC:+--func "$FUNC"} \
    --with-poc --out "$OUT_DIR/draft.md" 2>&1 | tail -5

# --- Step 5: Variant detector ---
echo ""
echo "[quick-mine] Step 5/6: Variant detector ..."
if [ -f "$OUT_DIR/draft.md" ]; then
    python3 "$AUDITOOOR_DIR/tools/variant-detector.py" "$WS" "$OUT_DIR/draft.md" \
        --json > "$OUT_DIR/variant-report.json" 2>&1
    RISK=$(python3 -c "import json; d=json.load(open('$OUT_DIR/variant-report.json')); print(d['risk_level'])")
    echo "[quick-mine] Dupe risk: $RISK"
    if [ "$RISK" = "HIGH" ]; then
        echo "[quick-mine] ⚠️  HIGH dupe risk — review variant-report.json before proceeding"
    fi
else
    echo "[quick-mine] Skipping variant detector (draft not generated)"
fi

# --- Step 6: Pre-submit check ---
echo ""
echo "[quick-mine] Step 6/6: Pre-submit check ..."
if [ -f "$OUT_DIR/draft.md" ]; then
    bash "$AUDITOOOR_DIR/tools/pre-submit-check.sh" "$OUT_DIR/draft.md" --fix 2>&1 | tee "$OUT_DIR/pre-submit.log" | tail -15
else
    echo "[quick-mine] Skipping pre-submit check (draft not generated)"
fi

# --- Summary ---
echo ""
echo "==========================================================================="
echo "  Quick Mine Complete — $ANGLE_ID on $CONTRACT"
echo "==========================================================================="
echo ""
echo "  Output directory: $OUT_DIR"
echo ""
echo "  Files generated:"
[ -f "$OUT_DIR/brief.md" ] && echo "    📋 brief.md       — Investigation plan"
[ -f "$OUT_DIR/snapshot.md" ] && echo "    🔍 snapshot.md    — Contract summary"
[ -f "$OUT_DIR/poc.t.sol" ] && echo "    🧪 poc.t.sol      — PoC scaffold"
[ -f "$OUT_DIR/draft.md" ] && echo "    📝 draft.md       — Submission draft"
[ -f "$OUT_DIR/variant-report.json" ] && echo "    ⚠️  variant-report.json — Dupe risk assessment"
[ -f "$OUT_DIR/pre-submit.log" ] && echo "    ✅ pre-submit.log  — Pre-submit check results"
echo ""
echo "  Next steps:"
echo "    1. Review brief.md and snapshot.md"
echo "    2. Fill in poc.t.sol with actual attack sequence"
echo "    3. Complete draft.md (replace TODOs)"
echo "    4. Run forge test to verify PoC"
echo "    5. If pre-submit passes: submit to platform"
echo ""
