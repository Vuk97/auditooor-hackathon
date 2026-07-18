#!/usr/bin/env bash
# memory-watcher-hourly-rollup.sh — ACT-17 §3
#
# Runs as a cron job every hour.  Summarises per-event notes in
#   obsidian-vault/events/<YYYY-MM-DD>/<HH>/*.md
# into a compact per-hour rollup:
#   obsidian-vault/events/<YYYY-MM-DD>/HOURLY-<HH>.md
#
# Install via crontab (hourly):
#   0 * * * * bash /path/to/tools/memory-watcher-hourly-rollup.sh
#
# Retention policy (enforced each run):
#   - Per-event notes: kept for 7 days, then deleted
#   - Hourly rollups:  kept for 30 days, then deleted
#   - Daily rollups:   kept forever (ACT-18 concern; not managed here)
#
# Usage:
#   bash tools/memory-watcher-hourly-rollup.sh [--vault-dir <dir>] [--dry-run]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VAULT_DIR="$REPO_ROOT/obsidian-vault"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-dir) VAULT_DIR="$2"; shift 2 ;;
    --dry-run)   DRY_RUN=1; shift ;;
    -h|--help)
      grep '^#' "$0" | head -25 | sed 's/^# \?//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

EVENTS_DIR="$VAULT_DIR/events"

if [[ ! -d "$EVENTS_DIR" ]]; then
  echo "[rollup] events dir not found: $EVENTS_DIR — nothing to do"
  exit 0
fi

# Current timestamp
NOW_DATE="$(date -u +%Y-%m-%d)"
NOW_HOUR="$(date -u +%H)"

# ── 1. Emit hourly rollup for the PREVIOUS hour (completed window) ──────────
PREV_HOUR="$(date -u -v-1H +%H 2>/dev/null || date -u -d '-1 hour' +%H 2>/dev/null || echo "$NOW_HOUR")"
PREV_DATE="$(date -u -v-1H +%Y-%m-%d 2>/dev/null || date -u -d '-1 hour' +%Y-%m-%d 2>/dev/null || echo "$NOW_DATE")"

ROLLUP_CMD="python3 $SCRIPT_DIR/memory-event-watcher.py \
  --vault-dir $VAULT_DIR \
  --hourly-rollup $PREV_DATE:$PREV_HOUR"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[rollup] DRY RUN — would execute: $ROLLUP_CMD"
else
  echo "[rollup] Generating rollup for $PREV_DATE $PREV_HOUR:00 UTC"
  eval "$ROLLUP_CMD" || echo "[rollup] WARN: rollup command returned non-zero"
fi

# ── 2. Prune per-event notes older than 7 days ─────────────────────────────
PRUNE_CUTOFF_EVENTS=7
echo "[rollup] Pruning per-event notes older than ${PRUNE_CUTOFF_EVENTS} days..."
pruned_events=0
while IFS= read -r -d '' note; do
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[rollup] DRY RUN — would prune: $note"
  else
    rm -f "$note"
  fi
  ((pruned_events++)) || true
done < <(find "$EVENTS_DIR" -maxdepth 3 \
    -name '????????.md' \
    -not -name 'HOURLY-*.md' \
    -mtime +"$PRUNE_CUTOFF_EVENTS" \
    -print0 2>/dev/null)

echo "[rollup] Per-event notes pruned: $pruned_events"

# ── 3. Prune hourly rollup notes older than 30 days ────────────────────────
PRUNE_CUTOFF_HOURLY=30
echo "[rollup] Pruning hourly rollups older than ${PRUNE_CUTOFF_HOURLY} days..."
pruned_hourly=0
while IFS= read -r -d '' rollup; do
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[rollup] DRY RUN — would prune: $rollup"
  else
    rm -f "$rollup"
  fi
  ((pruned_hourly++)) || true
done < <(find "$EVENTS_DIR" -maxdepth 2 \
    -name 'HOURLY-*.md' \
    -mtime +"$PRUNE_CUTOFF_HOURLY" \
    -print0 2>/dev/null)

echo "[rollup] Hourly rollups pruned: $pruned_hourly"

echo "[rollup] Done — $PREV_DATE/$PREV_HOUR rollup complete."
