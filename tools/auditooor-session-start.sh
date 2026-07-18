#!/usr/bin/env bash
# auditooor-session-start.sh — Tool-agnostic Layer-1 MCP recall runner.
#
# Runs the canonical Layer-1 vault_resume_context recall and writes
# .auditooor/last_mcp_recall.json as a freshness witness for git hooks and
# other enforcement tooling.
#
# Usage:
#   bash tools/auditooor-session-start.sh [workspace_path]
#
# workspace_path defaults to the git toplevel of the current working directory.
#
# Exit codes:
#   0  success — JSON sentinel written
#   1  MCP server call failed or workspace is invalid

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve workspace path
# ---------------------------------------------------------------------------
if [[ $# -ge 1 ]]; then
    WS="$1"
else
    WS="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi

if [[ ! -d "$WS" ]]; then
    echo "[session-start] ERROR: workspace '$WS' does not exist" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Detect owner tool from environment
# ---------------------------------------------------------------------------
if [[ -n "${AUDITOOOR_OWNER_TOOL:-}" ]]; then
    OWNER_TOOL="$AUDITOOOR_OWNER_TOOL"
elif [[ -n "${CLAUDE_CODE_ENTRYPOINT:-}" ]] || [[ -n "${CLAUDE_API_KEY:-}" ]]; then
    OWNER_TOOL="CLAUDE_CODE"
elif [[ -n "${CODEX_API_KEY:-}" ]] || [[ -n "${CODEX_THREAD_ID:-}" ]] || [[ -n "${CODEX_CI:-}" ]] || [[ -n "${CODEX_MANAGED_BY_NPM:-}" ]] || [[ "${0}" == *codex* ]]; then
    OWNER_TOOL="CODEX"
elif [[ -n "${KIMI_API_KEY:-}" ]] || [[ "${0}" == *kimi* ]]; then
    OWNER_TOOL="KIMI"
elif [[ -n "${CURSOR_WORKSPACE:-}" ]]; then
    OWNER_TOOL="CURSOR"
elif [[ -n "${AIDER_MODEL:-}" ]]; then
    OWNER_TOOL="AIDER"
else
    OWNER_TOOL="GENERIC"
fi

# ---------------------------------------------------------------------------
# Locate vault-mcp-server.py relative to this script
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_SERVER="$SCRIPT_DIR/vault-mcp-server.py"

if [[ ! -f "$MCP_SERVER" ]]; then
    echo "[session-start] ERROR: vault-mcp-server.py not found at '$MCP_SERVER'" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Run Layer-1 MCP recall sequence (promoted Wave-7 callables)
# ---------------------------------------------------------------------------
echo "[session-start] Running Layer-1 MCP recall sequence for workspace: $WS"

# Run all Layer-1 callables; collect output from vault_resume_context (the primary one)
MCP_ARGS="{\"workspace_path\":\"$WS\",\"limit\":4}"

MCP_OUTPUT="$(python3 "$MCP_SERVER" --call vault_resume_context --args "$MCP_ARGS" 2>&1)" || {
    echo "[session-start] ERROR: vault_resume_context call failed" >&2
    echo "$MCP_OUTPUT" >&2
    exit 1
}

# Secondary Layer-1 callables (promoted Wave-7)
echo "[session-start] Pulling secondary Layer-1 callables..."
python3 "$MCP_SERVER" --call vault_exploit_context --args "{\"workspace_path\":\"$WS\",\"limit\":5}" >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_knowledge_gap_context --args "{\"workspace_path\":\"$WS\",\"limit\":5}" >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_engagement_status --args "{\"workspace_path\":\"$WS\"}" >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_harness_context --args "{\"workspace_path\":\"$WS\",\"limit\":5}" >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_outcome_context --args "{\"workspace_path\":\"$WS\",\"limit\":5}" >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_dispatch_context --args "{\"workspace_path\":\"$WS\",\"limit\":5}" >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_goal_state --args '{}' >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_next_loop --args '{"limit":5}' >/dev/null 2>&1 || true
python3 "$MCP_SERVER" --call vault_llm_calibration --args "{\"workspace_path\":\"$WS\"}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Workspace staleness check (CAP-MORPHO-D)
# ---------------------------------------------------------------------------
STALENESS_TOOL="$SCRIPT_DIR/workspace-staleness-check.py"
if [[ -f "$STALENESS_TOOL" ]]; then
    echo "[session-start] Running workspace staleness check..."
    python3 "$STALENESS_TOOL" --workspace "$WS" 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Scope pin audit: detect POST-AUDIT-DEPLOYED contracts (CAP-MORPHO-C)
# ---------------------------------------------------------------------------
PIN_AUDIT_TOOL="$SCRIPT_DIR/post-audit-deployed-contract-detector.py"
if [[ -f "$PIN_AUDIT_TOOL" ]]; then
    echo "[session-start] Running scope pin audit..."
    python3 "$PIN_AUDIT_TOOL" --workspace "$WS" 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Extract context_pack_id and context_pack_hash from output
# ---------------------------------------------------------------------------
CONTEXT_PACK_ID="$(echo "$MCP_OUTPUT" | python3 -c "
import sys, json

raw = sys.stdin.read()
# Find first '{' to skip log lines
idx = raw.find('{')
if idx < 0:
    sys.exit(1)
try:
    obj = json.loads(raw[idx:])
except json.JSONDecodeError:
    sys.exit(1)
print(obj.get('context_pack_id', ''))
" 2>/dev/null)" || { echo "[session-start] ERROR: failed to parse context_pack_id" >&2; exit 1; }

CONTEXT_PACK_HASH="$(echo "$MCP_OUTPUT" | python3 -c "
import sys, json

raw = sys.stdin.read()
idx = raw.find('{')
if idx < 0:
    sys.exit(1)
try:
    obj = json.loads(raw[idx:])
except json.JSONDecodeError:
    sys.exit(1)
print(obj.get('context_pack_hash', ''))
" 2>/dev/null)" || { echo "[session-start] ERROR: failed to parse context_pack_hash" >&2; exit 1; }

if [[ -z "$CONTEXT_PACK_ID" || -z "$CONTEXT_PACK_HASH" ]]; then
    echo "[session-start] ERROR: MCP output missing context_pack_id or context_pack_hash" >&2
    echo "$MCP_OUTPUT" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build and write the JSON sentinel
# ---------------------------------------------------------------------------
RECALL_TS="$(python3 -c "import time; print(time.time())")"
RECALL_ISO="$(python3 -c "import datetime; print(datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'))")"

SENTINEL_DIR="$WS/.auditooor"
mkdir -p "$SENTINEL_DIR"

SENTINEL_FILE="$SENTINEL_DIR/last_mcp_recall.json"

# ---------------------------------------------------------------------------
# Gap #50 (codified 2026-05-26): auto-prune stale-expired pathspec intents
# at session start. SESSION-GAP-HUNT surfaced 6+ stale intents persisting
# across an operator session; pruning at session-start keeps the pathspec
# lean for the upcoming session's commit-hook diagnostics. The prune is
# best-effort: failure here MUST NOT block the session. Set
# GAP50_DISABLE_SESSION_START=1 to skip.
# ---------------------------------------------------------------------------
if [[ "${GAP50_DISABLE_SESSION_START:-}" != "1" ]]; then
    REGISTER_TOOL="$SCRIPT_DIR/agent-pathspec-register.py"
    if [[ -f "$REGISTER_TOOL" ]]; then
        echo "[session-start] (Gap #50) Pruning stale pathspec intents..."
        (cd "$WS" && python3 "$REGISTER_TOOL" prune 2>&1 || true)
    fi
fi

python3 - <<EOF
import json
data = {
    "context_pack_id": "$CONTEXT_PACK_ID",
    "context_pack_hash": "$CONTEXT_PACK_HASH",
    "workspace_path": "$WS",
    "recall_ts": $RECALL_TS,
    "recall_iso": "$RECALL_ISO",
    "owner_tool": "$OWNER_TOOL",
}
with open("$SENTINEL_FILE", "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print("[session-start] Sentinel written:", "$SENTINEL_FILE")
print("[session-start] context_pack_id:", data["context_pack_id"])
print("[session-start] context_pack_hash:", data["context_pack_hash"])
EOF
