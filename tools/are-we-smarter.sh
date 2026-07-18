#!/usr/bin/env bash
# are-we-smarter.sh — per-round self-improvement evaluator.
#
# Compares the current auditooor repo state to the baseline (R37) and emits
# a markdown report:
#   - DSL pattern count
#   - Wave17 compiled-detector count
#   - Tier-S / Tier-D counts (from _tier_registry.yaml)
#   - Rejection-classifier accuracy (from reference/rejection_classifier_history.yaml
#     if present, else N/A)
#   - Real-engagement TP count (from detectors/_hits_ledger.yaml)
#
# Then pulls git log, iterates over "Round N:" commits, and prints an ASCII
# growth-velocity chart.
#
# Usage:
#   ./tools/are-we-smarter.sh [--out <file>]
#
# If --out is omitted, prints to stdout.
#
# Fixes SKILL_ISSUES #154: "no quantitative answer to 'is the skill getting
# smarter'". Intended to run at the end of every shipping round.

set -uo pipefail

OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        -h|--help)
            sed -n '1,25p' "$0"
            exit 0 ;;
        *) shift ;;
    esac
done

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AUDITOOOR_DIR"

# ---------- Baseline figures (R37, pre-R38) ----------
BASE_PATTERNS=186
BASE_DETECTORS=186
BASE_TIER_S=1
BASE_TIER_D=3
BASE_REAL_TP=2
BASELINE_LABEL="Polymarket R37"

# ---------- Current counts ----------
# R45 bugfix (Bug 4): pattern-count drift.
# Prior impl had subtle non-determinism because:
#   (a) shell glob expansion order depends on LC_COLLATE (can swap files in/out
#       across runs on case-insensitive filesystems like macOS APFS),
#   (b) `ls` on a failed glob prints the literal pattern to stdout, which then
#       gets piped to wc -l and counted as "1".
# Fix: canonicalise the list (LC_ALL=C, `--` guard, explicit nullglob behaviour
# via 2>/dev/null+head) and always pipe through `grep -v __pycache__` even
# though the top-level glob shouldn't capture it — defensive, cheap, makes the
# count stable across runs.
PATTERNS_NOW=$(LC_ALL=C ls -1 reference/patterns.dsl/ 2>/dev/null \
                 | grep -E '\.yaml$' | grep -v '__pycache__' | wc -l | tr -d ' ')
DETECTORS_NOW=$(LC_ALL=C ls -1 detectors/wave17/ 2>/dev/null \
                 | grep -E '\.py$' | grep -v '__pycache__' | wc -l | tr -d ' ')

TIER_S_NOW=0
TIER_D_NOW=0
if [ -f detectors/_tier_registry.yaml ]; then
    TIER_S_NOW=$(grep -c "^    tier: S$" detectors/_tier_registry.yaml 2>/dev/null || echo 0)
    TIER_D_NOW=$(grep -c "^    tier: D$" detectors/_tier_registry.yaml 2>/dev/null || echo 0)
fi

# ---------- Rejection classifier accuracy ----------
CLASSIFIER_ACC="N/A"
if [ -f reference/rejection_classifier_history.yaml ]; then
    LATEST_ACC=$(grep -E "^\s*accuracy:" reference/rejection_classifier_history.yaml 2>/dev/null \
                   | tail -1 | awk '{print $2}')
    [ -n "$LATEST_ACC" ] && CLASSIFIER_ACC="$LATEST_ACC"
fi
BASELINE_CLASSIFIER_ACC="78%"

# ---------- Real-engagement TP count (from hits ledger) ----------
REAL_TP_NOW=0
if [ -f detectors/_hits_ledger.yaml ]; then
    # Sum the 'tp:' lines at the detector top-level
    REAL_TP_NOW=$(awk '
        /^[a-z][a-z0-9_-]+:$/ { in_det=1 }
        /^  tp: [0-9]+$/ && in_det { sum += $2; in_det=2 }
    ' detectors/_hits_ledger.yaml | tail -1)
    # Simpler: just sum all tp: values
    REAL_TP_NOW=$(grep -E "^\s+tp: [0-9]+" detectors/_hits_ledger.yaml 2>/dev/null \
                    | awk '{s += $2} END {print s+0}')
fi

# ---------- Ledger size (count detector entries under 'detectors:') ----------
LEDGER_SIZE=0
if [ -f detectors/_hits_ledger.yaml ]; then
    LEDGER_SIZE=$(grep -cE "^  [a-z][a-z0-9_-]+:$" detectors/_hits_ledger.yaml 2>/dev/null || echo 0)
fi

# ---------- Helper: compute % delta ----------
pct_delta() {
    local base="$1" now="$2"
    if [ "$base" -eq 0 ]; then
        [ "$now" -gt 0 ] && printf "+INF%%" || printf "0%%"
        return
    fi
    local d=$(( (now - base) * 100 / base ))
    if [ "$d" -ge 0 ]; then
        printf "+%d%%" "$d"
    else
        printf "%d%%" "$d"
    fi
}

PATTERNS_D=$(pct_delta $BASE_PATTERNS $PATTERNS_NOW)
DETECTORS_D=$(pct_delta $BASE_DETECTORS $DETECTORS_NOW)
TIER_S_D=$(pct_delta $BASE_TIER_S $TIER_S_NOW)
TIER_D_D=$(pct_delta $BASE_TIER_D $TIER_D_NOW)
REAL_TP_D=$(pct_delta $BASE_REAL_TP $REAL_TP_NOW)

# ---------- Verdict ----------
# Count pos/neg deltas to decide.
POS=0; NEG=0
score_delta() {
    local base="$1" now="$2"
    if [ "$now" -gt "$base" ]; then
        POS=$((POS+1))
    elif [ "$now" -lt "$base" ]; then
        NEG=$((NEG+1))
    fi
}
score_delta "$BASE_PATTERNS"  "$PATTERNS_NOW"
score_delta "$BASE_DETECTORS" "$DETECTORS_NOW"
score_delta "$BASE_TIER_S"    "$TIER_S_NOW"
score_delta "$BASE_REAL_TP"   "$REAL_TP_NOW"

if [ "$POS" -ge 3 ] && [ "$NEG" -eq 0 ]; then
    VERDICT="IMPROVING"
    VERDICT_MSG="Most deltas positive, no regressions — skill is getting smarter."
elif [ "$NEG" -ge 2 ]; then
    VERDICT="REGRESSED"
    VERDICT_MSG="Two or more deltas negative — investigate what was lost."
else
    VERDICT="STAGNATED"
    VERDICT_MSG="Mixed signal — neither clearly improving nor regressing."
fi

# ---------- Growth velocity ----------
# Pull each "Round N:" commit, measure pattern count at that rev (lightweight: just
# count yamls at that rev via git ls-tree).
growth_table() {
    echo "| Round | Commit | Patterns | Detectors | Ledger |"
    echo "|-------|--------|---------:|----------:|-------:|"
    # Gather round commits (newest-first)
    git log --oneline --grep="^Round [0-9]" 2>/dev/null | head -15 | awk '{print $1, $2, $3}' | \
    while read -r hash word1 word2; do
        # Word1 is "Round" and word2 is "N:" or "N"
        round=$(echo "$word2" | tr -d ':')
        # Measure patterns.dsl yaml count at this commit (R45 bugfix Bug 4:
        # filter __pycache__ explicitly so historical commits that accidentally
        # checked in .pyc/pycache artifacts don't poison the count).
        p_count=$(git ls-tree -r "$hash" -- reference/patterns.dsl 2>/dev/null \
                    | grep -v '__pycache__' | grep -cE "\.yaml$" || echo 0)
        d_count=$(git ls-tree -r "$hash" -- detectors/wave17 2>/dev/null \
                    | grep -v '__pycache__' | grep -cE "\.py$" || echo 0)
        l_size=0
        if git cat-file -e "$hash:detectors/_hits_ledger.yaml" 2>/dev/null; then
            l_size=$(git show "$hash:detectors/_hits_ledger.yaml" 2>/dev/null | grep -cE "^  [a-z][a-z0-9_-]+:$" || echo 0)
            # Fall back to top-level pattern for pre-R38 ledger format
            if [ "$l_size" = "0" ]; then
                l_size=$(git show "$hash:detectors/_hits_ledger.yaml" 2>/dev/null | grep -cE "^[a-z][a-z0-9_-]+:$" || echo 0)
            fi
        fi
        printf "| R%s | %s | %d | %d | %d |\n" "$round" "$hash" "$p_count" "$d_count" "$l_size"
    done
}

# ---------- ASCII velocity chart ----------
ascii_chart() {
    echo '```'
    echo "Growth velocity — pattern count per round (newest on top)"
    echo ""
    local max=$PATTERNS_NOW
    # Get recent rounds' pattern counts
    git log --oneline --grep="^Round [0-9]" 2>/dev/null | head -10 | awk '{print $1, $2, $3}' | \
    while read -r hash word1 word2; do
        round=$(echo "$word2" | tr -d ':')
        p_count=$(git ls-tree -r "$hash" -- reference/patterns.dsl 2>/dev/null | grep -cE "\.yaml$" || echo 0)
        # Bar width: scale to 40
        if [ "$max" -gt 0 ]; then
            bar_w=$(( p_count * 40 / max ))
        else
            bar_w=0
        fi
        bar=$(printf '%*s' "$bar_w" '' | tr ' ' '#')
        printf "R%-4s %s %d\n" "$round" "$bar" "$p_count"
    done
    echo '```'
}

# ---------- Emit report ----------
emit_report() {
    cat <<EOF
# Self-improvement evaluation ($(date +%Y-%m-%d))

## Stats (baseline: $BASELINE_LABEL)

- **DSL patterns:** ${BASE_PATTERNS} → ${PATTERNS_NOW} (${PATTERNS_D})
- **Wave17 detectors:** ${BASE_DETECTORS} → ${DETECTORS_NOW} (${DETECTORS_D})
- **Tier-S:** ${BASE_TIER_S} → ${TIER_S_NOW} (${TIER_S_D})
- **Tier-D explicit quarantine:** ${BASE_TIER_D} → ${TIER_D_NOW} (${TIER_D_D})
- **Rejection classifier accuracy:** ${BASELINE_CLASSIFIER_ACC} → ${CLASSIFIER_ACC}
- **Real-engagement TP count:** ${BASE_REAL_TP} → ${REAL_TP_NOW} (${REAL_TP_D})
- **Hits-ledger size:** ${LEDGER_SIZE} detectors tracked

## Verdict: **${VERDICT}**

${VERDICT_MSG}

## Growth velocity — last 15 rounds

$(growth_table)

## ASCII chart — pattern count by round

$(ascii_chart)

---

*Generated by \`tools/are-we-smarter.sh\` on $(date -u +%Y-%m-%dT%H:%M:%SZ)*
EOF
}

REPORT="$(emit_report)"

if [ -n "$OUT" ]; then
    printf '%s\n' "$REPORT" > "$OUT"
    echo "Report written to: $OUT" >&2
else
    printf '%s\n' "$REPORT"
fi
