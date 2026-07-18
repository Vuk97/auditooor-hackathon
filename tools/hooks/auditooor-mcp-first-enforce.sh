#!/usr/bin/env bash
# auditooor-mcp-first-enforce.sh
# PreToolUse hook on the Agent tool. HARD-BLOCKS audit-workspace agent
# dispatches whose prompt lacks an MCP-first recall block.
#
# Extended (Phase-II.14 I2 SPAWN-WORKER-ENFORCE, 2026-05-25):
# Also checks that the dispatch was routed through spawn-worker.sh before
# reaching the Agent tool. Detection is via:
#   (a) AUDITOOOR_SPAWN_WORKER_OK env var present in the current shell, OR
#   (b) A spawn_worker_log.jsonl entry whose ts is within the last 30 min
#       for any lane_id (indicates spawn-worker.sh was invoked in this session).
# Bypass: AUDITOOOR_SPAWN_WORKER_BYPASS=1 skips the spawn-worker check and
# writes an audit log entry.
#
# Decision contract (PreToolUse JSON):
#   - not an Agent dispatch / no prompt         -> allow (exit 0, no output)
#   - Agent dispatch, not audit-related         -> allow
#   - Agent dispatch, has bypass env            -> allow (audit-logged)
#   - Agent dispatch, audit-related, has MCP
#     AND spawn-worker routing confirmed         -> allow
#   - Agent dispatch, audit-related, has MCP
#     but NO spawn-worker routing               -> DENY with spawn-worker
#                                                  remediation message
#   - Agent dispatch, audit-related, no MCP    -> DENY with MCP remediation
#
# Fail-open: if jq is unavailable or stdin is unparseable, allow (never
# break all Agent dispatches because of a hook bug).
#
# Environment:
#   AUDITOOOR_SPAWN_WORKER_OK      Set by spawn-worker.sh to signal that the
#                                  dispatch was routed through the wrapper.
#   AUDITOOOR_SPAWN_WORKER_BYPASS  Set to "1" to skip spawn-worker check.
#                                  Use only for emergency or legacy cases.
#                                  The bypass is audit-logged.
#   SPAWN_WORKER_LOG_PATH          Override for spawn_worker_log.jsonl path.
#   AUDITOOOR_SPAWN_WORKER_RECENT_MIN
#                                  Lookback window in minutes (default: 30).

set -uo pipefail

REPO_ROOT="$(git -C /Users/wolf/auditooor-mcp rev-parse --show-toplevel 2>/dev/null || echo /Users/wolf/auditooor-mcp)"
DEFAULT_LOG_PATH="${REPO_ROOT}/.auditooor/spawn_worker_log.jsonl"
SPAWN_LOG="${SPAWN_WORKER_LOG_PATH:-$DEFAULT_LOG_PATH}"
RECENT_MIN="${AUDITOOOR_SPAWN_WORKER_RECENT_MIN:-30}"
DEFAULT_BYPASS_LOG="${REPO_ROOT}/.auditooor/spawn_worker_bypass_audit.jsonl"
BYPASS_LOG="${AUDITOOOR_BYPASS_LOG_PATH:-$DEFAULT_BYPASS_LOG}"

input="$(cat)"

# Extract the Agent tool's prompt. Non-Agent tools / parse failure -> empty.
prompt="$(printf '%s' "$input" | jq -r '.tool_input.prompt // ""' 2>/dev/null)"

# No prompt -> nothing to inspect -> allow.
[ -z "$prompt" ] && exit 0

# Is this an audit-workspace dispatch?
if printf '%s' "$prompt" | grep -Eiq '/audits/|auditooor|\b(nuva|spark|dydx|centrifuge|morpho|mezo|polymarket|hyperbridge|near)\b'; then
  : # audit dispatch - continue to checks
else
  exit 0  # non-audit Agent dispatch -> allow
fi

# ----- BYPASS CHECK -----
if [ "${AUDITOOOR_SPAWN_WORKER_BYPASS:-}" = "1" ]; then
  # Allowed but audit-logged.
  TS_NOW="$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))' 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")"
  mkdir -p "$(dirname "$BYPASS_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","event":"spawn-worker-bypass","env":"AUDITOOOR_SPAWN_WORKER_BYPASS=1","hook":"auditooor-mcp-first-enforce.sh"}\n' "$TS_NOW" >> "$BYPASS_LOG" 2>/dev/null || true
  exit 0
fi

# ----- MCP CHECK -----
has_mcp=0
if printf '%s' "$prompt" | grep -Eq 'vault-mcp-server\.py --call|vault_resume_context|context_pack_id|mcp__auditooor-vault'; then
  has_mcp=1
fi

if [ "$has_mcp" -eq 0 ]; then
  # Audit dispatch with NO MCP-first recall block -> HARD BLOCK.
  cat <<'EOF'
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "MCP-first enforcement (auditooor): this Agent dispatch targets an audit workspace but the prompt contains NO MCP recall block. Per ~/.claude/CLAUDE.md, every worker brief MUST embed an MCP-first recall block. Fix: add `python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_resume_context --args {\"workspace_path\":\"<ws>\",\"limit\":4}` to the agent prompt and record the context_pack_id. Then route through `bash /Users/wolf/auditooor-mcp/tools/spawn-worker.sh --lane-id <id> --lane-type <type> --severity <s> --workspace <ws> --prompt-file <file>` before re-issuing the Agent call."
  }
}
EOF
  exit 0
fi

# ----- SPAWN-WORKER ROUTING CHECK -----
spawn_ok=0

# (a) Check env var (fastest path - set by spawn-worker.sh)
if [ "${AUDITOOOR_SPAWN_WORKER_OK:-}" = "1" ]; then
  spawn_ok=1
fi

# (b) Check spawn_worker_log.jsonl for a recent entry (last N minutes)
if [ "$spawn_ok" -eq 0 ] && [ -f "$SPAWN_LOG" ]; then
  # Parse the timestamp from the last few entries using python3
  spawn_ok=$(python3 - <<PYEOF 2>/dev/null
import json
import sys
from datetime import datetime, timezone, timedelta

log_path = "$SPAWN_LOG"
recent_min = $RECENT_MIN
cutoff = datetime.now(timezone.utc) - timedelta(minutes=recent_min)

found = 0
try:
    with open(log_path, "r", encoding="utf-8") as fh:
        # Read last 50 lines for efficiency
        lines = fh.readlines()[-50:]
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        ts_str = row.get("ts", "")
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            continue
        if ts >= cutoff:
            found = 1
            break
except Exception:
    pass

print(found)
PYEOF
  )
  spawn_ok="${spawn_ok:-0}"
fi

if [ "$spawn_ok" = "1" ]; then
  exit 0  # spawn-worker routing confirmed -> allow
fi

# Audit dispatch with MCP but NO spawn-worker routing -> DENY.
cat <<'EOF'
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "spawn-worker enforcement (auditooor): this Agent dispatch targets an audit workspace but was NOT routed through spawn-worker.sh. Per WIRING-COMPLETENESS-V3 GAP-1 + Phase-II.14 I2, all Agent dispatches MUST go through `bash /Users/wolf/auditooor-mcp/tools/spawn-worker.sh`. Steps: (1) Write prompt to a file, (2) run `bash /Users/wolf/auditooor-mcp/tools/spawn-worker.sh --lane-id <lane-id> --lane-type <hunt|dispute|filing|escalation> --severity <LOW|MEDIUM|HIGH|CRITICAL> --workspace <ws-path> --prompt-file <prompt.md>`, (3) use the enriched prompt path it prints on stdout for the Agent call. Emergency bypass: `export AUDITOOOR_SPAWN_WORKER_BYPASS=1` (audit-logged). Lookback window: last 30 minutes of spawn_worker_log.jsonl entries."
  }
}
EOF
exit 0
