#!/usr/bin/env bash
# stop-task-finalization-hook.sh — Claude Stop/SubagentStop finalization gate.
#
# Reads the active dispatch manifest and writes a stable status packet under
# <workspace>/.auditooor/sessionend_finalization_status.json. By default this
# hook blocks when terminal manifest rows lack canonical task-finalization
# ledger closure. Set AUDITOOOR_FINALIZATION_REQUIRED=0 for an audit-logged
# bypass during transition.

set -euo pipefail

if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    WS="$CLAUDE_PROJECT_DIR"
elif [[ -n "${AUDITOOOR_WS:-}" ]]; then
    WS="$AUDITOOOR_WS"
else
    WS="$(pwd)"
fi

WS="$(cd "$WS" 2>/dev/null && pwd || echo "$WS")"
TOOL="$WS/tools/task-finalization-ledger.py"
OUT_DIR="$WS/.auditooor"
OUT="$OUT_DIR/sessionend_finalization_status.json"

mkdir -p "$OUT_DIR"

if [[ ! -f "$TOOL" ]]; then
    cat >"$OUT" <<EOF
{
  "schema": "auditooor.task_finalization_enforce_active_manifest.v1",
  "workspace": "${WS}",
  "status": "tool_missing",
  "completion_gap_count": 0,
  "completion_gaps": [],
  "enforced": false,
  "reason": "tools/task-finalization-ledger.py not found"
}
EOF
    exit 0
fi

if python3 "$TOOL" enforce-active-manifest --workspace "$WS" --out "$OUT" >/dev/null 2>&1; then
    exit 0
fi

echo "[stop-task-finalization-hook] active dispatch manifest has unfinalized terminal rows: $OUT" >&2
if [[ "${AUDITOOOR_FINALIZATION_REQUIRED:-1}" = "0" ]]; then
    printf '{"ts":"%s","event":"bypass","hook":"stop-task-finalization-hook","reason":"finalization_gap","status_file":"%s"}\n' \
        "$(date -u +%FT%TZ)" "$OUT" >> "$OUT_DIR/bypass_log.jsonl"
    exit 0
fi

exit 1
