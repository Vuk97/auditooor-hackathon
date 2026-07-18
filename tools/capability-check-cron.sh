#!/usr/bin/env bash
# capability-check-cron.sh - Daily cron wrapper for capability readiness dashboard.
#
# Runs the dashboard with --strict --json, commits health JSON to
# .auditooor/capability_health_history/, and emits a vault_remember alert
# if any capability regression is detected.
#
# Usage: bash tools/capability-check-cron.sh [--workspace <ws>] [--no-commit] [--no-alert]
#
# Environment:
#   AUDITOOOR_CAP_WORKSPACE  Override repo root (default: script's repo root)
#   AUDITOOOR_CAP_NO_COMMIT  Set to 1 to skip git commit step
#   AUDITOOOR_CAP_NO_ALERT   Set to 1 to skip vault_remember alert step

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WS="${AUDITOOOR_CAP_WORKSPACE:-$REPO_ROOT}"
NO_COMMIT="${AUDITOOOR_CAP_NO_COMMIT:-0}"
NO_ALERT="${AUDITOOOR_CAP_NO_ALERT:-0}"

# Parse CLI overrides
while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)  WS="$2"; shift 2 ;;
    --no-commit)  NO_COMMIT=1; shift ;;
    --no-alert)   NO_ALERT=1; shift ;;
    *) echo "[WARN] Unknown arg: $1" >&2; shift ;;
  esac
done

TODAY="$(date -u +%Y-%m-%d)"
LOG_PREFIX="[capability-check-cron $TODAY]"
HEALTH_JSON="$WS/.auditooor/capability_health.json"
HEALTH_HIST_DIR="$WS/.auditooor/capability_health_history"

echo "$LOG_PREFIX starting capability readiness run..."

# ---------------------------------------------------------------------------
# Step 1: Ensure inventory is fresh (build if needed)
# ---------------------------------------------------------------------------
INVENTORY="$WS/reference/capability_inventory.jsonl"
if [[ ! -f "$INVENTORY" ]]; then
  echo "$LOG_PREFIX inventory not found, building..."
  python3 "$WS/tools/capability-inventory-build.py" --json >"$WS/.auditooor/cap_inventory_build_$TODAY.json" 2>&1 || {
    echo "$LOG_PREFIX [ERROR] inventory build failed" >&2
    exit 1
  }
fi

# ---------------------------------------------------------------------------
# Step 2: Run dashboard with --strict --json --diff-yesterday
# ---------------------------------------------------------------------------
DASHBOARD_OUT="$WS/.auditooor/capability_health_$TODAY.json"

python3 "$WS/tools/capability-readiness-dashboard.py" \
  --strict \
  --json \
  --diff-yesterday \
  --inventory "$INVENTORY" \
  >"$DASHBOARD_OUT" 2>&1
DASHBOARD_RC=$?

# Copy to canonical location (save_health_json already does this, but ensure it exists)
if [[ -f "$HEALTH_JSON" ]]; then
  mkdir -p "$HEALTH_HIST_DIR"
  cp "$HEALTH_JSON" "$HEALTH_HIST_DIR/$TODAY.json" 2>/dev/null || true
fi

# Parse summary from JSON output
TOTAL=$(python3 -c "import json,sys; d=json.load(open('$DASHBOARD_OUT')); print(d.get('total',0))" 2>/dev/null || echo "?")
RED=$(python3 -c "import json,sys; d=json.load(open('$DASHBOARD_OUT')); print(d.get('by_verdict',{}).get('RED',0))" 2>/dev/null || echo "?")
GREEN=$(python3 -c "import json,sys; d=json.load(open('$DASHBOARD_OUT')); print(d.get('by_verdict',{}).get('GREEN',0))" 2>/dev/null || echo "?")
REGRESSIONS=$(python3 -c "import json,sys; d=json.load(open('$DASHBOARD_OUT')); print(d.get('regression_count',0))" 2>/dev/null || echo "?")

echo "$LOG_PREFIX total=$TOTAL GREEN=$GREEN RED=$RED regressions=$REGRESSIONS"

# ---------------------------------------------------------------------------
# Step 3: Commit health JSON to history (R36: explicit pathspec only)
# ---------------------------------------------------------------------------
if [[ "$NO_COMMIT" != "1" ]]; then
  cd "$WS"
  HIST_FILE=".auditooor/capability_health_history/$TODAY.json"
  if [[ -f "$HIST_FILE" ]]; then
    # R36 discipline: explicit pathspec
    git add -- "$HIST_FILE" ".auditooor/capability_health.json" 2>/dev/null || true
    STAGED=$(git diff --staged --name-only 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$STAGED" -gt 0 ]]; then
      git commit -- "$HIST_FILE" ".auditooor/capability_health.json" \
        -m "cron: capability health snapshot $TODAY (GREEN=$GREEN RED=$RED regressions=$REGRESSIONS)" \
        2>/dev/null || {
          echo "$LOG_PREFIX [WARN] git commit failed (may be nothing to commit)" >&2
        }
    else
      echo "$LOG_PREFIX no changes to commit in health files"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Step 4: Alert via vault_remember if regressions detected
# ---------------------------------------------------------------------------
if [[ "$NO_ALERT" != "1" && "$REGRESSIONS" != "0" && "$REGRESSIONS" != "?" ]]; then
  REGRESSION_IDS=$(python3 -c "
import json
d = json.load(open('$DASHBOARD_OUT'))
ids = [r['id'] for r in d.get('regressions', [])]
print(', '.join(ids[:5]))
" 2>/dev/null || echo "unknown")

  ALERT_MSG="CAPABILITY REGRESSION ALERT [$TODAY]: $REGRESSIONS regression(s) detected. Previously GREEN, now RED: $REGRESSION_IDS. Run: make capability-readiness-strict to reproduce."

  python3 "$WS/tools/vault-mcp-server.py" \
    --call vault_remember \
    --args "{\"workspace_path\":\"$WS\",\"key\":\"capability_regression_$TODAY\",\"value\":\"$ALERT_MSG\"}" \
    2>/dev/null || echo "$LOG_PREFIX [WARN] vault_remember alert failed (non-fatal)"

  echo "$LOG_PREFIX [ALERT] $ALERT_MSG"
fi

# ---------------------------------------------------------------------------
# Exit
# ---------------------------------------------------------------------------
if [[ "$DASHBOARD_RC" != "0" ]]; then
  echo "$LOG_PREFIX [FAIL] strict check failed: RED=$RED regressions=$REGRESSIONS"
  exit "$DASHBOARD_RC"
fi

echo "$LOG_PREFIX [PASS] capability readiness OK"
exit 0
