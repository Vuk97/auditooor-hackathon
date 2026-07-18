#!/usr/bin/env bash
# triage-to-draft.sh — R49 Track D: end-to-end pipeline wiring triage → draft.
#
# Reads <ws>/custom-detectors.log, groups hits by the detector ARGUMENT
# (`=== Running <name> ===` header), and for each top-10 cluster decides:
#   - Tier-S                     -> auto-call auto-draft.sh  (up to 3 drafts
#                                   for the first Tier-S cluster so the
#                                   smoke test has ≥3 to exercise)
#   - Tier-E with precision ≥0.5 -> auto-call auto-draft.sh  (1 draft)
#   - otherwise                  -> queue for manual triage
#
# Writes <ws>/drafts/_pipeline_summary.md and appends a `drafts_ready_auto`
# event to reference/timing_ledger.yaml (best-effort).
#
# Usage:
#   ./tools/triage-to-draft.sh <workspace>
#
# Exit codes:
#   0 — summary written (even if zero auto-drafts created)
#   1 — usage error
#   2 — required workspace file missing (custom-detectors.log)

set -u

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="$AUDITOOOR_DIR/tools"
AUTO_DRAFT="$TOOLS_DIR/auto-draft.sh"
DETECTOR_TIER="$TOOLS_DIR/detector-tier.sh"
TIME_ENG="$TOOLS_DIR/time-engagement.sh"

# Tunables
MAX_CLUSTERS=10              # only look at top-N detector clusters by hit count
MAX_DRAFTS_PER_CLUSTER=3     # cap drafts per cluster (applies to Tier-S)
TIER_E_MIN_PRECISION="0.5"   # ledger precision threshold for auto-drafting Tier-E

WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
    echo "usage: $0 <workspace>" >&2
    exit 1
fi

LOG="$WS/custom-detectors.log"
if [ ! -f "$LOG" ]; then
    echo "[triage-to-draft] missing $LOG — run tools/scan.sh first" >&2
    exit 2
fi

if [ ! -x "$AUTO_DRAFT" ]; then
    echo "[triage-to-draft] auto-draft.sh not executable at $AUTO_DRAFT" >&2
    exit 2
fi

DRAFT_DIR="$WS/drafts"
mkdir -p "$DRAFT_DIR"
SUMMARY="$DRAFT_DIR/_pipeline_summary.md"
: > "$SUMMARY"

T_START=$(date +%s)

# --- Extract hits keyed by detector ARGUMENT. -----------------------------
# Produces lines of the form:
#   <detector>\t<file:line>
# where file:line is the first `src/.../Contract.sol#NNN` reference in the
# [SEV] line. Multi-line ranges like `#640-674` are collapsed to the first
# number.
HITS_RAW=$(mktemp)
trap 'rm -f "$HITS_RAW" "$CLUSTERS" "$QUEUED" 2>/dev/null' EXIT
awk '
    /^=== Running / { det = $0; gsub(/^=== Running | ===$/, "", det); next }
    /^[[:space:]]*\[(HIGH|MEDIUM|LOW|INFO)\]/ {
        line = $0
        # Match (path.sol#N) OR (path.sol#N-M). Capture path and first N.
        if (match(line, /\([^()]*\.sol#[0-9]+(-[0-9]+)?\)/)) {
            seg = substr(line, RSTART+1, RLENGTH-2)
            split(seg, parts, "#")
            file = parts[1]
            n = parts[2]; sub(/-.*/, "", n)
            if (det != "" && file != "" && n != "") {
                print det "\t" file ":" n
            }
        }
    }
' "$LOG" > "$HITS_RAW"

TOTAL_HITS=$(wc -l < "$HITS_RAW" | tr -d ' ')

# --- Group by detector, rank by count. -------------------------------------
CLUSTERS=$(mktemp)
awk -F'\t' '{c[$1]++} END {for (d in c) print c[d] "\t" d}' "$HITS_RAW" \
  | sort -k1,1 -n -r | head -n "$MAX_CLUSTERS" > "$CLUSTERS"

TOTAL_CLUSTERS=$(wc -l < "$CLUSTERS" | tr -d ' ')

# --- Tier lookup helper (wraps detector-tier.sh show). ---------------------
# Sets globals TIER and PRECISION for the passed detector name.
lookup_tier() {
    local det="$1"
    TIER="D"
    PRECISION="0.00"
    if [ -x "$DETECTOR_TIER" ]; then
        local show
        show=$("$DETECTOR_TIER" show "$det" 2>/dev/null)
        TIER=$(printf '%s\n' "$show" | awk '/^[[:space:]]*Tier:/{print $2; exit}')
        [ -z "$TIER" ] && TIER="D"
        local prec
        prec=$(printf '%s\n' "$show" | sed -nE 's/.*precision=([0-9.]+).*/\1/p' | head -1)
        [ -n "$prec" ] && PRECISION="$prec"
    fi
}

# --- Numeric compare: returns 0 if $1 >= $2 (floats). ---------------------
float_ge() {
    awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 >= b+0)}'
}

# --- Pipeline loop. --------------------------------------------------------
QUEUED=$(mktemp)
: > "$QUEUED"

AUTO_DRAFTS_CREATED=0
AUTO_DRAFT_PATHS=""
CLUSTER_INDEX=0

# Write header early so failures mid-run still leave a summary stub.
{
    echo "# Triage-to-draft pipeline summary"
    echo
    echo "- Workspace:        \`$WS\`"
    echo "- Log:              \`$(basename "$LOG")\`"
    echo "- Total hits:       $TOTAL_HITS"
    echo "- Clusters (top $MAX_CLUSTERS): $TOTAL_CLUSTERS"
    echo "- Generated:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## Cluster decisions"
    echo
    echo "| # | Detector | Hits | Tier | Precision | Action |"
    echo "|---|----------|------|------|-----------|--------|"
} > "$SUMMARY"

while IFS=$'\t' read -r CNT DET; do
    CLUSTER_INDEX=$((CLUSTER_INDEX + 1))
    lookup_tier "$DET"

    ACTION=""
    DRAFT_CAP=0
    if [ "$TIER" = "S" ]; then
        DRAFT_CAP="$MAX_DRAFTS_PER_CLUSTER"
        ACTION="auto-draft (Tier-S, up to $DRAFT_CAP)"
    elif [ "$TIER" = "E" ] && float_ge "$PRECISION" "$TIER_E_MIN_PRECISION"; then
        DRAFT_CAP=1
        ACTION="auto-draft (Tier-E, prec=$PRECISION)"
    else
        DRAFT_CAP=0
        ACTION="manual queue"
        printf '%s\t%s\t%s\t%s\n' "$DET" "$CNT" "$TIER" "$PRECISION" >> "$QUEUED"
    fi

    printf '| %d | `%s` | %d | %s | %s | %s |\n' \
        "$CLUSTER_INDEX" "$DET" "$CNT" "$TIER" "$PRECISION" "$ACTION" >> "$SUMMARY"

    if [ "$DRAFT_CAP" -gt 0 ]; then
        # Pull up to DRAFT_CAP unique file:line hits for this detector.
        HITS_FOR_DET=$(awk -F'\t' -v d="$DET" '$1==d {print $2}' "$HITS_RAW" \
                      | awk '!seen[$0]++' | head -n "$DRAFT_CAP")

        IDX=0
        while IFS= read -r HIT; do
            [ -z "$HIT" ] && continue
            IDX=$((IDX + 1))
            # file path in log is repo-relative (`src/...`). Resolve against WS.
            FILE_REL="${HIT%:*}"
            LINE_NUM="${HIT##*:}"
            ABS_FILE="$WS/$FILE_REL"
            if [ ! -f "$ABS_FILE" ]; then
                # fall back to literal (already absolute?)
                if [ -f "$FILE_REL" ]; then
                    ABS_FILE="$FILE_REL"
                else
                    echo "[triage-to-draft] cluster $CLUSTER_INDEX/$IDX: source not found ($FILE_REL), skipping" >&2
                    continue
                fi
            fi

            echo "[triage-to-draft] drafting: $DET @ $ABS_FILE:$LINE_NUM" >&2
            # Snapshot drafts/ before so we can diff-detect the new file
            # rather than relying on mtime order.
            BEFORE=$(mktemp)
            ls "$DRAFT_DIR"/*_auto.md 2>/dev/null | sort > "$BEFORE"
            if "$AUTO_DRAFT" "$WS" "$DET" "$ABS_FILE:$LINE_NUM" >/dev/null 2>&1; then
                AFTER=$(mktemp)
                ls "$DRAFT_DIR"/*_auto.md 2>/dev/null | sort > "$AFTER"
                NEW_DRAFT=$(comm -13 "$BEFORE" "$AFTER" | head -1)
                rm -f "$AFTER"
                if [ -n "$NEW_DRAFT" ] && [ -f "$NEW_DRAFT" ]; then
                    AUTO_DRAFTS_CREATED=$((AUTO_DRAFTS_CREATED + 1))
                    AUTO_DRAFT_PATHS="${AUTO_DRAFT_PATHS}${NEW_DRAFT}"$'\n'
                else
                    # File reused (same slug) — touch the known output path by
                    # matching auto-draft's slug scheme. Fall back to mtime.
                    FALLBACK=$(ls -t "$DRAFT_DIR"/*_auto.md 2>/dev/null | head -1)
                    if [ -n "$FALLBACK" ]; then
                        AUTO_DRAFTS_CREATED=$((AUTO_DRAFTS_CREATED + 1))
                        AUTO_DRAFT_PATHS="${AUTO_DRAFT_PATHS}${FALLBACK}"$'\n'
                    fi
                fi
            else
                echo "[triage-to-draft] auto-draft.sh failed for $DET @ $ABS_FILE:$LINE_NUM (non-fatal)" >&2
            fi
            rm -f "$BEFORE"
        done <<< "$HITS_FOR_DET"
    fi
done < "$CLUSTERS"

# --- Summary tail. ---------------------------------------------------------
T_END=$(date +%s)
ELAPSED=$((T_END - T_START))

{
    echo
    echo "## Auto-drafts created ($AUTO_DRAFTS_CREATED)"
    echo
    if [ "$AUTO_DRAFTS_CREATED" -gt 0 ]; then
        printf '%s' "$AUTO_DRAFT_PATHS" | sed '/^$/d' | awk '{print "- `" $0 "`"}'
    else
        echo "_None — no Tier-S cluster in top-$MAX_CLUSTERS, and no Tier-E with precision ≥ $TIER_E_MIN_PRECISION._"
    fi

    echo
    QUEUED_COUNT=$(wc -l < "$QUEUED" | tr -d ' ')
    echo "## Manual triage queue ($QUEUED_COUNT clusters)"
    echo
    if [ "$QUEUED_COUNT" -gt 0 ]; then
        echo "| Detector | Hits | Tier | Precision |"
        echo "|----------|------|------|-----------|"
        awk -F'\t' '{printf "| `%s` | %s | %s | %s |\n", $1, $2, $3, $4}' "$QUEUED"
    else
        echo "_All top-$MAX_CLUSTERS clusters auto-drafted or skipped by design._"
    fi

    echo
    echo "## Timing"
    echo
    echo "- Wall-clock: ${ELAPSED}s"
} >> "$SUMMARY"

echo "[triage-to-draft] summary: $SUMMARY"
echo "[triage-to-draft] auto-drafts created: $AUTO_DRAFTS_CREATED"
echo "[triage-to-draft] manual queue:        $(wc -l < "$QUEUED" | tr -d ' ')"
echo "[triage-to-draft] elapsed:             ${ELAPSED}s"

# --- Chain: time-engagement.sh drafts_ready_auto (best-effort). ----------
if [ -x "$TIME_ENG" ] && [ "$AUTO_DRAFTS_CREATED" -gt 0 ]; then
    # The canonical event names in time-engagement.sh are scan_complete /
    # draft_ready / submission_filed; drafts_ready_auto is a Track-D
    # extension — append directly to the ledger when the script rejects it.
    if ! "$TIME_ENG" "$WS" drafts_ready_auto 2>/dev/null; then
        LEDGER="$AUDITOOOR_DIR/reference/timing_ledger.yaml"
        mkdir -p "$(dirname "$LEDGER")"
        WS_NAME=$(basename "${WS%/}")
        NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        if [ ! -f "$LEDGER" ]; then
            echo "events:" > "$LEDGER"
        elif grep -q '^events: \[\]' "$LEDGER"; then
            sed -i.bak 's/^events: \[\]/events:/' "$LEDGER" && rm -f "${LEDGER}.bak"
        fi
        {
            echo "  - workspace: $WS_NAME"
            echo "    event: drafts_ready_auto"
            echo "    timestamp: $NOW"
            echo "    count: $AUTO_DRAFTS_CREATED"
        } >> "$LEDGER"
        echo "[triage-to-draft] appended drafts_ready_auto ($AUTO_DRAFTS_CREATED) to timing_ledger.yaml"
    fi
fi

exit 0
