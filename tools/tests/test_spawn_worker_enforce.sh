#!/usr/bin/env bash
# test_spawn_worker_enforce.sh - Tests for spawn-worker.sh enforcement in
# auditooor-mcp-first-enforce.sh (Phase-II.14 I2 SPAWN-WORKER-ENFORCE).
#
# Test plan:
#   Test 1: Agent dispatch without spawn-worker.sh and without bypass
#           -> hook returns deny (spawn-worker remediation message)
#   Test 2: Agent dispatch with valid spawn_worker_log.jsonl entry (recent)
#           -> hook returns allow
#   Test 3: Agent dispatch with AUDITOOOR_SPAWN_WORKER_BYPASS=1
#           -> hook returns allow + audit-logged in bypass log
#   Test 4: spawn-worker.sh invocation writes log entry correctly
#           -> log entry has required keys
#   Test 5: log entry older than 30 min is not counted as recent
#           -> hook returns deny (spawn-worker remediation message)
#   Test 6: AUDITOOOR_SPAWN_WORKER_OK=1 env allows dispatch
#           -> hook returns allow
#   Test 7: Non-audit Agent dispatch passes without spawn-worker
#           -> hook returns allow (not audit-related)
#   Test 8: Audit dispatch with no MCP block gets MCP deny (not spawn-worker)
#           -> deny reason cites MCP, not spawn-worker
#
# Run: bash tools/tests/test_spawn_worker_enforce.sh
# All tests print PASS or FAIL + description.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOK="${HOME}/.claude/hooks/auditooor-mcp-first-enforce.sh"
SPAWN_TOOL="${REPO_ROOT}/tools/spawn-worker.sh"

PASS=0
FAIL=0
TOTAL=0

check() {
    local n="$1"; local desc="$2"; local result="$3"; local expected="$4"
    TOTAL=$((TOTAL + 1))
    if [ "$result" = "$expected" ]; then
        echo "  PASS Test $n: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL Test $n: $desc"
        echo "       expected: $expected"
        echo "       got:      $result"
        FAIL=$((FAIL + 1))
    fi
}

# Helper: invoke the hook with a given prompt and env, return decision
invoke_hook() {
    local prompt="$1"; shift
    local extra_env=("$@")
    # Build PreToolUse JSON payload
    local payload
    payload=$(python3 -c "
import json, sys
prompt = sys.argv[1]
print(json.dumps({'tool_name': 'Agent', 'tool_input': {'prompt': prompt}}))
" "$prompt")
    # Run hook with the payload as stdin
    local out
    out=$(env "${extra_env[@]}" bash "$HOOK" <<< "$payload" 2>/dev/null || true)
    # Extract permissionDecision from JSON output; if empty -> "allow" (exit 0, no deny output)
    if [ -z "$out" ]; then
        echo "allow"
    else
        echo "$out" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('hookSpecificOutput',{}).get('permissionDecision','allow'))" 2>/dev/null || echo "allow"
    fi
}

# Helper: extract permissionDecisionReason
invoke_hook_reason() {
    local prompt="$1"; shift
    local extra_env=("$@")
    local payload
    payload=$(python3 -c "
import json, sys
print(json.dumps({'tool_name': 'Agent', 'tool_input': {'prompt': sys.argv[1]}}))
" "$prompt")
    local out
    out=$(env "${extra_env[@]}" bash "$HOOK" <<< "$payload" 2>/dev/null || true)
    if [ -z "$out" ]; then
        echo ""
    else
        echo "$out" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('hookSpecificOutput',{}).get('permissionDecisionReason',''))" 2>/dev/null || echo ""
    fi
}

# Create temp directories for test isolation
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

AUDITOOOR_DIR="${TMP_DIR}/.auditooor"
mkdir -p "$AUDITOOOR_DIR"

LOG_PATH="${AUDITOOOR_DIR}/spawn_worker_log.jsonl"
BYPASS_LOG_PATH="${AUDITOOOR_DIR}/spawn_worker_bypass_audit.jsonl"

# Base audit prompt (has MCP block)
AUDIT_PROMPT_WITH_MCP="auditooor workspace: /audits/dydx. MCP recall: python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_resume_context --args '{\"workspace_path\":\"/audits/dydx\",\"limit\":4}'. context_pack_id: abc123."

# Audit prompt without MCP block
AUDIT_PROMPT_NO_MCP="Investigate dydx workspace for fund-loss issues. Begin search at /audits/dydx."

# Non-audit prompt
NON_AUDIT_PROMPT="Help me understand a Python script for data analysis."

echo "=== spawn-worker enforcement tests ==="
echo ""

# --------------------------------------------------------------------------
# Test 1: Audit dispatch with MCP block but no spawn-worker routing -> deny
# --------------------------------------------------------------------------
result=$(invoke_hook "$AUDIT_PROMPT_WITH_MCP" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=")
check 1 "audit+MCP but no spawn-worker routing -> deny" "$result" "deny"

# Also verify the deny reason mentions spawn-worker (not MCP)
reason=$(invoke_hook_reason "$AUDIT_PROMPT_WITH_MCP" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=")
if echo "$reason" | grep -q "spawn-worker"; then
    echo "  PASS Test 1b: deny reason cites spawn-worker"
    PASS=$((PASS + 1))
else
    echo "  FAIL Test 1b: deny reason does not cite spawn-worker (got: $reason)"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

# --------------------------------------------------------------------------
# Test 2: Valid spawn_worker_log.jsonl entry (recent) -> allow
# --------------------------------------------------------------------------
TS_NOW=$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))')
printf '{"ts":"%s","tool":"spawn-worker.sh","lane_id":"test-lane","schema":"auditooor.spawn_worker.v1","dispatch_guard_env":"AUDITOOOR_SPAWN_WORKER_OK"}\n' "$TS_NOW" > "$LOG_PATH"

result=$(invoke_hook "$AUDIT_PROMPT_WITH_MCP" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=")
check 2 "audit+MCP with recent log entry -> allow" "$result" "allow"

# Reset log
> "$LOG_PATH"

# --------------------------------------------------------------------------
# Test 3: AUDITOOOR_SPAWN_WORKER_BYPASS=1 -> allow + audit log written
# --------------------------------------------------------------------------
BYPASS_LOG_PATH="${AUDITOOOR_DIR}/spawn_worker_bypass_audit.jsonl"
result=$(invoke_hook "$AUDIT_PROMPT_WITH_MCP" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_BYPASS_LOG_PATH=$BYPASS_LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=1")
check 3 "AUDITOOOR_SPAWN_WORKER_BYPASS=1 -> allow" "$result" "allow"

# Check bypass audit log was written
BYPASS_LOG_CHECK="$BYPASS_LOG_PATH"
if [ -f "$BYPASS_LOG_CHECK" ] && grep -q "spawn-worker-bypass" "$BYPASS_LOG_CHECK"; then
    echo "  PASS Test 3b: bypass audit log written"
    PASS=$((PASS + 1))
else
    echo "  FAIL Test 3b: bypass audit log NOT written at $BYPASS_LOG_CHECK"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

# --------------------------------------------------------------------------
# Test 4: spawn-worker.sh writes log entry with required keys
# --------------------------------------------------------------------------
# Only run if spawn-worker.sh exists and is executable
if [ -f "$SPAWN_TOOL" ]; then
    SW_LOG="${TMP_DIR}/sw_test_log.jsonl"
    SW_TMP="${TMP_DIR}/sw_tmp"
    mkdir -p "$SW_TMP"
    SW_PROMPT="${TMP_DIR}/test_prompt.md"
    printf 'test prompt for lane4\n' > "$SW_PROMPT"

    SPAWN_WORKER_LOG_PATH="$SW_LOG" \
    SPAWN_WORKER_TMP_DIR="$SW_TMP" \
    SPAWN_WORKER_BYPASS_REASON="test" \
    bash "$SPAWN_TOOL" \
        --lane-id test-lane-4 \
        --lane-type hunt \
        --severity HIGH \
        --workspace "${TMP_DIR}" \
        --prompt-file "$SW_PROMPT" \
        --no-register \
        --no-prebriefing \
        >/dev/null 2>/dev/null || true

    if [ -f "$SW_LOG" ]; then
        row=$(tail -1 "$SW_LOG")
        has_ts=$(echo "$row" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print('ok' if d.get('ts') else 'missing')" 2>/dev/null)
        has_lane=$(echo "$row" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print('ok' if d.get('lane_id')=='test-lane-4' else 'missing')" 2>/dev/null)
        has_guard=$(echo "$row" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print('ok' if d.get('dispatch_guard_env')=='AUDITOOOR_SPAWN_WORKER_OK' else 'missing')" 2>/dev/null)
        if [ "$has_ts" = "ok" ] && [ "$has_lane" = "ok" ] && [ "$has_guard" = "ok" ]; then
            echo "  PASS Test 4: spawn-worker.sh writes log entry with required keys"
            PASS=$((PASS + 1))
        else
            echo "  FAIL Test 4: log entry missing keys (ts=$has_ts lane=$has_lane guard=$has_guard)"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "  FAIL Test 4: spawn-worker.sh did not write log file at $SW_LOG"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  SKIP Test 4: spawn-worker.sh not found at $SPAWN_TOOL"
fi
TOTAL=$((TOTAL + 1))

# --------------------------------------------------------------------------
# Test 5: Log entry older than 30 min -> deny (not counted as recent)
# --------------------------------------------------------------------------
OLD_TS=$(python3 -c 'from datetime import datetime,timezone,timedelta; print((datetime.now(timezone.utc)-timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))')
printf '{"ts":"%s","tool":"spawn-worker.sh","lane_id":"old-lane","schema":"auditooor.spawn_worker.v1","dispatch_guard_env":"AUDITOOOR_SPAWN_WORKER_OK"}\n' "$OLD_TS" > "$LOG_PATH"

result=$(invoke_hook "$AUDIT_PROMPT_WITH_MCP" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=")
check 5 "log entry >30 min old -> deny" "$result" "deny"

# Reset log
> "$LOG_PATH"

# --------------------------------------------------------------------------
# Test 6: AUDITOOOR_SPAWN_WORKER_OK=1 env -> allow
# --------------------------------------------------------------------------
result=$(invoke_hook "$AUDIT_PROMPT_WITH_MCP" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=1" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=")
check 6 "AUDITOOOR_SPAWN_WORKER_OK=1 env -> allow" "$result" "allow"

# --------------------------------------------------------------------------
# Test 7: Non-audit Agent dispatch -> allow (not subject to spawn-worker check)
# --------------------------------------------------------------------------
result=$(invoke_hook "$NON_AUDIT_PROMPT" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=")
check 7 "non-audit Agent dispatch -> allow" "$result" "allow"

# --------------------------------------------------------------------------
# Test 8: Audit dispatch with no MCP block -> deny citing MCP (not spawn-worker)
# --------------------------------------------------------------------------
reason=$(invoke_hook_reason "$AUDIT_PROMPT_NO_MCP" \
    "SPAWN_WORKER_LOG_PATH=$LOG_PATH" \
    "AUDITOOOR_SPAWN_WORKER_OK=" \
    "AUDITOOOR_SPAWN_WORKER_BYPASS=")
if echo "$reason" | grep -q "MCP-first enforcement" && ! echo "$reason" | grep -q "spawn-worker enforcement"; then
    echo "  PASS Test 8: no-MCP audit dispatch -> deny cites MCP enforcement (not spawn-worker)"
    PASS=$((PASS + 1))
else
    echo "  FAIL Test 8: unexpected reason (expected MCP-first, not spawn-worker): $reason"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
if [ "$FAIL" -eq 0 ]; then
    echo "All tests PASS"
    exit 0
else
    echo "$FAIL test(s) FAILED"
    exit 1
fi
