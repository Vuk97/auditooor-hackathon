#!/usr/bin/env bash
# sessionend-forever-loop-packet.sh — SessionEnd hook for forever-loop continuity.
#
# PR #658 Lane 7 — Worker-B1 deliverable.
#
# Emits <ws>/.auditooor/sessionend_packet.json on Claude session termination so
# the next forever-loop iteration can resume from a known state without needing
# interactive context reconstruction.
#
# Packet schema (auditooor.sessionend_packet.v1):
#   {
#     "schema": "auditooor.sessionend_packet.v1",
#     "session_ended_at": "<iso8601>",
#     "git_head": "<sha>",          # or "NOT_A_GIT_REPO" if not in git
#     "branch": "<name>",           # or "UNKNOWN" if detached / not in git
#     "workspace": "<abs_path>",
#     "next_loop_hint": "run forever-loop-mcp-bridge prime if no token, then resume"
#   }
#
# Workspace resolution priority:
#   1. $CLAUDE_PROJECT_DIR env var (set by Claude Code harness)
#   2. $AUDITOOOR_WS env var (manual override)
#   3. pwd
#
# Exits 0 silently if not in a git repo (git commands fail gracefully).
# Never prints the raw MCP token.

set -euo pipefail

# ---------------------------------------------------------------------------
# Workspace resolution
# ---------------------------------------------------------------------------
if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    WS="$CLAUDE_PROJECT_DIR"
elif [[ -n "${AUDITOOOR_WS:-}" ]]; then
    WS="$AUDITOOOR_WS"
else
    WS="$(pwd)"
fi

# Ensure absolute path
WS="$(cd "$WS" 2>/dev/null && pwd || echo "$WS")"

# ---------------------------------------------------------------------------
# Git metadata (graceful fallback if not a git repo)
# ---------------------------------------------------------------------------
GIT_HEAD="NOT_A_GIT_REPO"
BRANCH="UNKNOWN"

if git -C "$WS" rev-parse --git-dir >/dev/null 2>&1; then
    GIT_HEAD="$(git -C "$WS" rev-parse HEAD 2>/dev/null || echo 'UNKNOWN')"
    BRANCH="$(git -C "$WS" rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'UNKNOWN')"
fi

# ---------------------------------------------------------------------------
# Timestamp (ISO 8601 UTC)
# ---------------------------------------------------------------------------
SESSION_ENDED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# Output path
# ---------------------------------------------------------------------------
AUDITOOOR_DIR="$WS/.auditooor"
PACKET_PATH="$AUDITOOOR_DIR/sessionend_packet.json"
FINALIZATION_STATUS_PATH="$AUDITOOOR_DIR/sessionend_finalization_status.json"

mkdir -p "$AUDITOOOR_DIR"

# ---------------------------------------------------------------------------
# Emit packet (atomic: write tmp, then rename)
# ---------------------------------------------------------------------------
TMP_PATH="$PACKET_PATH.tmp.$$"

cat >"$TMP_PATH" <<EOF
{
  "schema": "auditooor.sessionend_packet.v1",
  "session_ended_at": "${SESSION_ENDED_AT}",
  "git_head": "${GIT_HEAD}",
  "branch": "${BRANCH}",
  "workspace": "${WS}",
  "next_loop_hint": "run forever-loop-mcp-bridge prime if no token, then resume"
}
EOF

mv "$TMP_PATH" "$PACKET_PATH"

# Best-effort finalization status packet. The blocking Stop/SubagentStop hook
# lives in stop-task-finalization-hook.sh; SessionEnd stays non-disruptive.
FINALIZATION_TOOL="$WS/tools/task-finalization-ledger.py"
if [[ -f "$FINALIZATION_TOOL" ]]; then
    python3 "$FINALIZATION_TOOL" enforce-active-manifest \
        --workspace "$WS" \
        --out "$FINALIZATION_STATUS_PATH" >/dev/null 2>&1 || true
fi

# Exit 0 silently — hook must not disrupt session teardown
exit 0
