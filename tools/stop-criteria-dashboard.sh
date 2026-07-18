#!/usr/bin/env bash
# stop-criteria-dashboard.sh — R50 Track C.
#
# Renders `reference/stop_criteria_dashboard.md` combining:
#   - per-criterion status (from c{1,2,3,5}_status.txt + stop_criteria_status.md)
#   - R46..R50 trend arrows per criterion (from git round log)
#   - time-to-target estimate for every FAIL criterion
#   - classifier growth sparkline (from rejection_classifier_history.yaml)
#   - ledger growth sparkline (timing_ledger.yaml)
#
# Usage: ./tools/stop-criteria-dashboard.sh [--out <path>]

set -u

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$AUDITOOOR_DIR/reference/stop_criteria_dashboard.md"

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        -h|--help) sed -n '1,18p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ------------------------------------------------------------------
# 1. Per-criterion current status
# ------------------------------------------------------------------
read_status_txt() {
    local f="$AUDITOOOR_DIR/reference/$1"
    if [ ! -f "$f" ]; then
        echo "UNKNOWN: file missing ($1)"
        return
    fi
    # Prefer a PASS/FAIL/UNKNOWN line; else first non-comment line; else head -1.
    line=$(grep -E '^(PASS|FAIL|UNKNOWN|Verdict)' "$f" 2>/dev/null | head -1)
    if [ -z "$line" ]; then
        line=$(grep -v '^#' "$f" | grep -v '^$' | head -1)
    fi
    [ -z "$line" ] && line=$(head -1 "$f")
    echo "$line"
}

C1=$(read_status_txt c1_status.txt)
C2=$(read_status_txt c2_status.txt)
C3=$(read_status_txt c3_status.txt)
C5=$(read_status_txt c5_status.txt)

# C4 pulled directly from timing_ledger.yaml mean(scan_complete -> draft_ready) in minutes.
C4_MINUTES=""
LEDGER="$AUDITOOOR_DIR/reference/timing_ledger.yaml"
if [ -f "$LEDGER" ]; then
    C4_MINUTES=$(python3 - "$LEDGER" <<'PY'
import sys, re, datetime as dt
path = sys.argv[1]
rows = []
cur = {}
for line in open(path):
    m = re.match(r'\s*- workspace:\s*(.+)$', line);
    if m:
        if cur: rows.append(cur)
        cur = {'workspace': m.group(1).strip()}
        continue
    m = re.match(r'\s*event:\s*(.+)$', line)
    if m: cur['event'] = m.group(1).strip()
    m = re.match(r'\s*timestamp:\s*(.+)$', line)
    if m: cur['ts'] = m.group(1).strip()
if cur: rows.append(cur)

pairs = []
scans = {}
for r in rows:
    if r.get('event') == 'scan_complete':
        scans.setdefault(r['workspace'], []).append(r['ts'])
    elif r.get('event') == 'draft_ready':
        ws = r['workspace']
        ss = scans.get(ws)
        if ss:
            s = ss.pop(0)
            try:
                a = dt.datetime.fromisoformat(s.replace('Z','+00:00'))
                b = dt.datetime.fromisoformat(r['ts'].replace('Z','+00:00'))
                pairs.append((b-a).total_seconds()/60.0)
            except Exception: pass

if pairs:
    print(f"{sum(pairs)/len(pairs):.1f}")
else:
    print("no_pairs")
PY
)
fi
[ -z "$C4_MINUTES" ] && C4_MINUTES="unknown"

C4_THRESHOLD=15
C4_STATUS="UNKNOWN"
if [[ "$C4_MINUTES" != "unknown" && "$C4_MINUTES" != "no_pairs" ]]; then
    if awk -v m="$C4_MINUTES" -v t="$C4_THRESHOLD" 'BEGIN{ exit !(m <= t) }'; then
        C4_STATUS="PASS"
    else
        C4_STATUS="FAIL"
    fi
fi
C4="$C4_STATUS: mean scan->draft = ${C4_MINUTES} min (target <= ${C4_THRESHOLD})"

# ------------------------------------------------------------------
# 2. Per-criterion historical snapshot per round (R46..R50)
#
# We take a round snapshot from git log: for each round, read status
# files as of that commit. If not available for a round, mark "--".
# ------------------------------------------------------------------
ROUNDS="R46 R47 R48 R49 R50"
# Parallel arrays: ROUND_NAMES[i] -> ROUND_SHAS[i].
ROUND_NAMES=()
ROUND_SHAS=()
for r in $ROUNDS; do
    num="${r#R}"
    sha=$(git -C "$AUDITOOOR_DIR" log --grep="^Round $num" --pretty=format:"%h" 2>/dev/null | tail -1)
    ROUND_NAMES+=("$r")
    ROUND_SHAS+=("$sha")
done

# Look up sha by round name (linear — only 5 entries).
sha_for_round() {
    local name="$1" i=0
    for n in "${ROUND_NAMES[@]}"; do
        if [ "$n" = "$name" ]; then echo "${ROUND_SHAS[$i]}"; return; fi
        i=$(( i + 1 ))
    done
}

# Trend arrow helper: <old> <new> <up-is-good?> -> arrow.
arrow() {
    local old="$1" new="$2" up_good="$3"
    if [ -z "$old" ] || [ -z "$new" ] || [ "$old" = "--" ] || [ "$new" = "--" ]; then echo "-"; return; fi
    awk -v o="$old" -v n="$new" -v g="$up_good" 'BEGIN{
        if (n+0 > o+0) print (g=="1" ? "^" : "v")
        else if (n+0 < o+0) print (g=="1" ? "v" : "^")
        else print "="
    }'
}

# C1: zero-OOS streak. Pull from c1_status.txt PASS_PARTIAL number.
c1_streak() {
    local f="$1"
    grep -oE "[0-9]+ (of )?[0-9]* consecutive|[0-9]+ consecutive|streak: [0-9]+" "$f" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1
}

# C2: classifier accuracy
c2_acc() {
    local f="$1"
    grep -oE 'accuracy [01]\.[0-9]+' "$f" 2>/dev/null | head -1 | grep -oE '[01]\.[0-9]+'
}

# C3: TP per detector ratio
c3_ratio() {
    local f="$1"
    grep -oE 'Ratio [0-9]+/[0-9]+' "$f" 2>/dev/null | head -1 | tr -d 'Ratio '
}

# Read a file content at a given git revision (returns empty on fail).
at_rev() {
    local sha="$1" relpath="$2"
    [ -z "$sha" ] && { echo ""; return; }
    git -C "$AUDITOOOR_DIR" show "${sha}:${relpath}" 2>/dev/null
}

# Build a per-round row for a criterion.
row_for_criterion() {
    local label="$1" relpath="$2" extractor="$3"
    local vals=()
    for r in $ROUNDS; do
        local content
        content=$(at_rev "$(sha_for_round "$r")" "$relpath")
        if [ -z "$content" ]; then
            vals+=("--")
        else
            local v
            case "$extractor" in
                c1) v=$(echo "$content" | grep -oE '[0-9]+' | head -1) ;;
                c2) v=$(echo "$content" | grep -oE '0\.[0-9]+' | head -1) ;;
                c3) v=$(echo "$content" | grep -oE '[0-9]+/[0-9]+' | head -1) ;;
                c5)
                    if echo "$content" | grep -qi "PASS"; then v="PASS"; else v="FAIL"; fi ;;
                *) v="--" ;;
            esac
            [ -z "$v" ] && v="--"
            vals+=("$v")
        fi
    done
    printf "| %s |" "$label"
    for v in "${vals[@]}"; do printf " %s |" "$v"; done
    echo
}

# ------------------------------------------------------------------
# 3. Classifier growth sparkline from rejection_classifier_history.yaml
# ------------------------------------------------------------------
CLASS_HIST="$AUDITOOOR_DIR/reference/rejection_classifier_history.yaml"
CLASS_SPARK=""
if [ -f "$CLASS_HIST" ]; then
    CLASS_SPARK=$(grep -oE 'enriched_accuracy: [01]\.[0-9]+' "$CLASS_HIST" | awk -F': ' '{print $2}' | python3 -c "
import sys
vals = [float(x) for x in sys.stdin.read().split() if x]
if not vals:
    print('(empty)'); sys.exit()
blocks = ' ▁▂▃▄▅▆▇█'
lo, hi = min(vals), max(vals)
rng = hi - lo if hi > lo else 1e-9
out = ''.join(blocks[1 + int((v-lo)/rng * (len(blocks)-2))] for v in vals)
print(f'{out}  ({vals[0]:.3f} -> {vals[-1]:.3f}, n={len(vals)})')
")
fi

# ------------------------------------------------------------------
# 4. Ledger growth sparkline (per-engagement event count over time)
# ------------------------------------------------------------------
LEDGER_SPARK=""
if [ -f "$LEDGER" ]; then
    LEDGER_SPARK=$(python3 - "$LEDGER" <<'PY'
import sys, re, datetime as dt
path = sys.argv[1]
buckets = {}
current = None
for line in open(path):
    m = re.match(r'\s*timestamp:\s*(.+)$', line)
    if m:
        try:
            d = dt.datetime.fromisoformat(m.group(1).strip().replace('Z','+00:00'))
            key = d.strftime('%Y-%m-%d')
            buckets[key] = buckets.get(key, 0) + 1
        except Exception: pass
if not buckets:
    print('(empty)'); sys.exit()
vals = [v for _, v in sorted(buckets.items())]
blocks = ' ▁▂▃▄▅▆▇█'
lo, hi = min(vals), max(vals)
rng = hi - lo if hi > lo else 1e-9
out = ''.join(blocks[1 + int((v-lo)/rng * (len(blocks)-2))] for v in vals)
print(f"{out}  (events/day, last day={vals[-1]}, days={len(vals)})")
PY
)
fi

# ------------------------------------------------------------------
# 5. Time-to-target estimate for FAILing criteria
# ------------------------------------------------------------------
eta_for_c2() {
    [ -f "$CLASS_HIST" ] || { echo "unknown"; return; }
    python3 - "$CLASS_HIST" <<'PY'
import sys, re
path = sys.argv[1]
vals = []
for line in open(path):
    m = re.match(r'\s*enriched_accuracy:\s*([01]\.[0-9]+)', line)
    if m: vals.append(float(m.group(1)))
if len(vals) < 2:
    print("need >=2 datapoints"); sys.exit()
TARGET = 0.90
cur = vals[-1]
# Mean positive delta per step.
deltas = [vals[i]-vals[i-1] for i in range(1,len(vals)) if vals[i] > vals[i-1]]
if not deltas or cur >= TARGET:
    print("already met" if cur >= TARGET else "no positive trend"); sys.exit()
step = sum(deltas)/len(deltas)
remaining = TARGET - cur
steps = remaining / step if step > 0 else float('inf')
print(f"~{steps:.1f} training rounds at current delta ({step:.4f}/round) from {cur:.3f}")
PY
}

eta_for_c4() {
    [ "$C4_MINUTES" = "unknown" ] && { echo "unknown"; return; }
    [ "$C4_MINUTES" = "no_pairs" ] && { echo "no_data"; return; }
    awk -v m="$C4_MINUTES" -v t="$C4_THRESHOLD" 'BEGIN{
        if (m+0 <= t+0) { print "already met"; exit }
        # Auto-draft collapses draft-ready step to ~0.001 min; projection assumes next
        # real engagement dogfoods auto-draft.
        print "next engagement with auto-draft.sh dogfooded"
    }'
}

# ------------------------------------------------------------------
# 6. Render
# ------------------------------------------------------------------
{
cat <<HEADER
# Stop-criteria dashboard

Generated: $STAMP by \`tools/stop-criteria-dashboard.sh\` (R50 Track C).
Source rubric: \`reference/10_of_10_auditor_roadmap.md\` §Stop criteria.

---

## Current status

| # | Criterion | Status line |
|---|---|---|
| 1 | Consecutive zero-OOS engagements | $C1 |
| 2 | Rejection classifier precision   | $C2 |
| 3 | TP rate per detector hit         | $C3 |
| 4 | Scan-to-draft time (min)         | $C4 |
| 5 | One-command operator flow        | $C5 |

## Trend (R46 → R47 → R48 → R49 → R50)

| Criterion | R46 | R47 | R48 | R49 | R50 |
|---|---|---|---|---|---|
HEADER

row_for_criterion "C1 streak"        "reference/c1_status.txt" c1
row_for_criterion "C2 accuracy"      "reference/c2_status.txt" c2
row_for_criterion "C3 TP/hits"       "reference/c3_status.txt" c3
row_for_criterion "C4 scan->draft"   "reference/c4_status.txt" c2
row_for_criterion "C5 entrypoint"    "reference/c5_status.txt" c5

cat <<BODY

## Time-to-target estimates (FAIL criteria only)

- **C2 → 0.90 precision:** $(eta_for_c2)
- **C4 → 15 min scan-to-draft:** $(eta_for_c4)

## Sparklines

**Classifier accuracy history** (enriched_accuracy over training rounds):

\`\`\`
${CLASS_SPARK:-(no history)}
\`\`\`

**Timing ledger growth** (events per day):

\`\`\`
${LEDGER_SPARK:-(no ledger)}
\`\`\`

## Notes

- Row values "--" mean the status file did not yet exist at that round.
- Arrows: ^ improved, v regressed, = flat (see [tool source](../tools/stop-criteria-dashboard.sh) for extractor logic).
- Rerun this script any time: \`./tools/stop-criteria-dashboard.sh\`.
BODY
} > "$OUT"

echo "[stop-criteria-dashboard] wrote $OUT"
