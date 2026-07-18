#!/usr/bin/env bash
# time-engagement.sh — append a timing event to reference/timing_ledger.yaml (R47 C4).
#
# Usage:
#   ./tools/time-engagement.sh <workspace> <event-name>
#
# <event-name> must be one of:
#   scan_complete       — scan.sh just finished
#   draft_ready         — first /drafts/*.md committed
#   submission_filed    — finding submitted to bounty platform
#
# The ledger is append-only YAML at auditooor/reference/timing_ledger.yaml.
# Consumed by are-we-smarter.sh (mean scan-to-draft minutes) and
# stop-criteria-check.sh (C4 cycle-time criterion).
#
# Exit codes:
#   0 — event appended
#   1 — usage error
#   2 — unknown event name

set -u

WS="${1:-}"
EVENT="${2:-}"

if [ -z "$WS" ] || [ -z "$EVENT" ]; then
    echo "usage: $0 <workspace> <event-name>" >&2
    echo "       events: scan_complete | draft_ready | submission_filed" >&2
    exit 1
fi

case "$EVENT" in
    scan_complete|draft_ready|submission_filed) ;;
    *)
        echo "[time-engagement] unknown event: $EVENT" >&2
        echo "       events: scan_complete | draft_ready | submission_filed" >&2
        exit 2
        ;;
esac

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="$AUDITOOOR_DIR/reference/timing_ledger.yaml"

# Basename only — strip any trailing slash, resolve to folder name.
WS_NAME=$(basename "${WS%/}")
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Initialize ledger with header if missing.
if [ ! -f "$LEDGER" ]; then
    cat > "$LEDGER" <<'HDR'
# timing_ledger.yaml — engagement-phase timing events (R47 C4).
#
# Appended to by tools/time-engagement.sh. Consumed by:
#   - tools/are-we-smarter.sh   → mean scan-to-draft minutes
#   - tools/stop-criteria-check.sh → C4 (cycle-time) criterion

events: []
HDR
fi

# Append a new row. If the ledger still has the empty-seed `events: []` line
# replace it with `events:` + a first row; else just append to the existing list.
if grep -q '^events: \[\]' "$LEDGER"; then
    # Portable in-place edit (no sed -i difference across BSD/GNU).
    TMP="${LEDGER}.tmp.$$"
    awk -v ws="$WS_NAME" -v ev="$EVENT" -v ts="$NOW" '
        /^events: \[\]/ {
            print "events:"
            print "  - workspace: " ws
            print "    event: " ev
            print "    timestamp: " ts
            next
        }
        { print }
    ' "$LEDGER" > "$TMP" && mv "$TMP" "$LEDGER"
else
    {
        echo "  - workspace: $WS_NAME"
        echo "    event: $EVENT"
        echo "    timestamp: $NOW"
    } >> "$LEDGER"
fi

echo "[time-engagement] $WS_NAME :: $EVENT @ $NOW"
