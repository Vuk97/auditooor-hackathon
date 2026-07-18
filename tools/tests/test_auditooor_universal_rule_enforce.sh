#!/usr/bin/env bash
# Test harness for tools/hooks/auditooor-universal-rule-enforce.sh.
#
# Runs the hook with synthetic PreToolUse payloads against the 8 seed
# action classes plus their override paths. Tracks pass/fail count.
# Each test case maps to operator's mandatory "Tests" list in the brief.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." >/dev/null 2>&1 && pwd)"
HOOK="${REPO_ROOT}/tools/hooks/auditooor-universal-rule-enforce.sh"

# Isolate the audit log so tests do not contaminate the real one.
TMPDIR_TEST="$(mktemp -d)"
export AUDITOOOR_UNIVERSAL_LOG_PATH="${TMPDIR_TEST}/test_log.jsonl"

pass=0
fail=0
failed_cases=()

assert_deny() {
  local name="$1" payload="$2"
  local out
  out="$(printf '%s' "$payload" | bash "$HOOK" 2>&1)"
  if printf '%s' "$out" | grep -q '"permissionDecision":\s*"deny"'; then
    pass=$((pass + 1))
    echo "PASS: $name"
  else
    fail=$((fail + 1))
    failed_cases+=("$name")
    echo "FAIL: $name"
    echo "  got: $out"
  fi
}

assert_allow() {
  local name="$1" payload="$2"
  local out
  out="$(printf '%s' "$payload" | bash "$HOOK" 2>&1)"
  if printf '%s' "$out" | grep -q '"permissionDecision":\s*"deny"'; then
    fail=$((fail + 1))
    failed_cases+=("$name")
    echo "FAIL: $name (expected allow, got deny)"
    echo "  got: $out"
  else
    pass=$((pass + 1))
    echo "PASS: $name"
  fi
}

# ---------------------------------------------------------------------------
# Test 1: git commit without context_pack_id -> BLOCK (operator-mandated)
# ---------------------------------------------------------------------------

assert_deny "test1-git-commit-no-context-pack" \
  '{"tool_name":"Bash","tool_input":{"command":"git commit -m \"misc\""}}'

# Test 1b: git commit WITH context_pack_id in message -> ALLOW
assert_allow "test1b-git-commit-with-context-pack-id" \
  '{"tool_name":"Bash","tool_input":{"command":"git commit -m \"foo\\n\\ncontext_pack_id: auditooor.vault_context_pack.v1:resume:abc\\ncontext_pack_hash: deadbeef\""}}'

# ---------------------------------------------------------------------------
# Test 2: Edit on submissions/paste_ready/foo/foo.md without L34 cite -> BLOCK
# ---------------------------------------------------------------------------

assert_deny "test2-edit-draft-no-l34-cite" \
  '{"tool_name":"Edit","tool_input":{"file_path":"/Users/wolf/audits/hyperbridge/submissions/paste_ready/foo/foo.md","old_string":"x","new_string":"y"}}'

# Test 2b: Edit on draft WITH l34-rebuttal in new_string -> ALLOW
assert_allow "test2b-edit-draft-with-l34-rebuttal" \
  '{"tool_name":"Edit","tool_input":{"file_path":"/Users/wolf/audits/hyperbridge/submissions/paste_ready/foo/foo.md","old_string":"x","new_string":"<!-- l34-rebuttal: operator approved fix per ticket -->"}}'

# ---------------------------------------------------------------------------
# Test 3: Agent severity-decision context without Rule 14 cite -> BLOCK
# ---------------------------------------------------------------------------

assert_deny "test3-agent-severity-decision-no-r14" \
  '{"tool_name":"Agent","tool_input":{"prompt":"Lane: SEVERITY-ESCALATION for finding. Decide on severity upgrade for dydx submission."}}'

# ---------------------------------------------------------------------------
# Test 4: Same Agent dispatch WITH r14-rebuttal -> ALLOW
# ---------------------------------------------------------------------------

assert_allow "test4-agent-severity-with-r14-rebuttal" \
  '{"tool_name":"Agent","tool_input":{"prompt":"Lane: SEVERITY-ESCALATION for dydx finding. Decide on severity upgrade. <!-- r14-rebuttal: explicit-not-applicable: program does not allow upgrade-amend -->"}}'

# Test 4b: Agent severity with tools/triager-amend-asymmetry.py cite -> ALLOW
assert_allow "test4b-agent-severity-with-triager-tool-cite" \
  '{"tool_name":"Agent","tool_input":{"prompt":"Lane: SEVERITY-ESCALATION. Run python3 tools/triager-amend-asymmetry.py --workspace ws --candidate-severity HIGH first."}}'

# ---------------------------------------------------------------------------
# Test 5: Bash ls -> ALLOW (no rule citation needed for read-only ls)
# ---------------------------------------------------------------------------

assert_allow "test5-bash-ls-allowed" \
  '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'

# ---------------------------------------------------------------------------
# Test 6: Bash unrelated dev work (cd polymarket, npm test) -> ALLOW
# ---------------------------------------------------------------------------

assert_allow "test6-bash-unrelated-dev-work" \
  '{"tool_name":"Bash","tool_input":{"command":"cd /Users/wolf/Downloads/GTO_WEBSITE && npm test"}}'

# ---------------------------------------------------------------------------
# Additional coverage:
# ---------------------------------------------------------------------------

# Test 7: git reset --hard -> BLOCK via R55
assert_deny "test7-git-reset-hard-blocked-r55" \
  '{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}'

# Test 7b: git reset --hard with R55_REBUTTAL env -> ALLOW
R55_REBUTTAL="operator approved cleanup sweep" \
assert_allow "test7b-git-reset-hard-r55-env-rebuttal" \
  '{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}'

# Test 8: Write tools/foo.py without R36 cite -> BLOCK
assert_deny "test8-write-tools-py-no-r36" \
  '{"tool_name":"Write","tool_input":{"file_path":"/Users/wolf/auditooor-mcp/tools/foo.py","content":"print(1)"}}'

# Test 8b: Write tools/foo.py with R36 cite (agent-pathspec-register mention) -> ALLOW
assert_allow "test8b-write-tools-py-with-r36-cite" \
  '{"tool_name":"Write","tool_input":{"file_path":"/Users/wolf/auditooor-mcp/tools/foo.py","content":"# registered via tools/agent-pathspec-register.py per R36"}}'

# Test 9: Bash bypass via env -> ALLOW
AUDITOOOR_UNIVERSAL_BYPASS=1 \
assert_allow "test9-bash-with-bypass-env" \
  '{"tool_name":"Bash","tool_input":{"command":"git commit -m foo"}}'

# Test 10: Read submissions/paste_ready/foo/foo.md -> ALLOW (reads always allowed)
assert_allow "test10-read-draft-always-allowed" \
  '{"tool_name":"Read","tool_input":{"file_path":"/Users/wolf/audits/hyperbridge/submissions/paste_ready/foo/foo.md"}}'

# Test 11: Drill-class Agent dispatch without hacker-mcp cite -> BLOCK
assert_deny "test11-drill-lane-no-hacker-mcp" \
  '{"tool_name":"Agent","tool_input":{"prompt":"DRILL-7 lane: novel-vector hunt for hyperbridge"}}'

# Test 11b: Drill-class with vault_hacker_brief_for_lane cite -> ALLOW
assert_allow "test11b-drill-lane-with-hacker-mcp-cite" \
  '{"tool_name":"Agent","tool_input":{"prompt":"DRILL-7 lane. python3 tools/vault-mcp-server.py --call vault_hacker_brief_for_lane --args {} required first."}}'

# Test 12: git push without MCP token -> BLOCK
assert_deny "test12-git-push-no-mcp-token" \
  '{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}'

# Test 12b: git push with MCP token env -> ALLOW
AUDITOOOR_MCP_SESSION_TOKEN="abc.def.ghi" \
assert_allow "test12b-git-push-with-mcp-token-env" \
  '{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}'

# Test 13: Edit submissions/SUBMISSIONS.md tracker -> ALLOW
assert_allow "test13-edit-submissions-md-tracker-allowed" \
  '{"tool_name":"Edit","tool_input":{"file_path":"/Users/wolf/audits/spark/submissions/SUBMISSIONS.md","old_string":"x","new_string":"y"}}'

# Test 14: Empty stdin -> ALLOW (fail-open)
assert_allow "test14-empty-stdin-allowed" \
  ''

# ===========================================================================
# Phase 1 Tier-A EXTREME-gap hook-integration tests (18 cases).
# 6 block + 6 in-content rebuttal pass + 6 env-var override.
#
# Spec: reports/v3_iter_2026-05-26/lane_ENFORCEMENT_AUDIT/phase1_extension_recommendations.md
# Lane: ENFORCEMENT-PHASE-1-TIER-A-6-EXTREME-GAPS-CLOSURE
# ===========================================================================

# --- Gap 1: --no-verify ----------------------------------------------------

assert_deny "gap1-block: git commit --no-verify" \
  '{"tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m foo"}}'

assert_allow "gap1-rebuttal: shell-comment rebuttal token" \
  '{"tool_name":"Bash","tool_input":{"command":"# extreme-rebuttal-gap1-no-verify: operator-driven debug; CI exempt\ngit commit --no-verify -m foo"}}'

AUDITOOOR_NEVER_SKIP_HOOKS_BYPASS=1 \
assert_allow "gap1-env-override: AUDITOOOR_NEVER_SKIP_HOOKS_BYPASS=1" \
  '{"tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m foo"}}'

# --- Gap 2: force push to main/master/HEAD ---------------------------------

assert_deny "gap2-block: git push -f origin main" \
  '{"tool_name":"Bash","tool_input":{"command":"git push -f origin main"}}'

assert_allow "gap2-rebuttal: shell-comment rebuttal" \
  '{"tool_name":"Bash","tool_input":{"command":"# extreme-rebuttal-gap2-force-push-main: operator-approved recovery from corrupted history\ngit push -f origin main"}}'

AUDITOOOR_NEVER_FORCE_PUSH_BYPASS=1 \
assert_allow "gap2-env-override: AUDITOOOR_NEVER_FORCE_PUSH_BYPASS=1" \
  '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}'

# --- Gap 3: git config WRITE -----------------------------------------------

assert_deny "gap3-block: git config --global user.email" \
  '{"tool_name":"Bash","tool_input":{"command":"git config --global user.email foo@bar.com"}}'

assert_allow "gap3-rebuttal: shell-comment rebuttal" \
  '{"tool_name":"Bash","tool_input":{"command":"# extreme-rebuttal-gap3-git-config-write: operator-explicit identity setup for fresh worktree\ngit config --global user.email foo@bar.com"}}'

AUDITOOOR_NEVER_GIT_CONFIG_BYPASS=1 \
assert_allow "gap3-env-override: AUDITOOOR_NEVER_GIT_CONFIG_BYPASS=1" \
  '{"tool_name":"Bash","tool_input":{"command":"git config --local commit.gpgsign false"}}'

# --- Gap 4: gh gist delete -------------------------------------------------

assert_deny "gap4-block: gh gist delete" \
  '{"tool_name":"Bash","tool_input":{"command":"gh gist delete abc123def"}}'

assert_allow "gap4-rebuttal: shell-comment rebuttal" \
  '{"tool_name":"Bash","tool_input":{"command":"# extreme-rebuttal-gap4-gist-delete: gist contains accidental secret leak; URL preservation moot\ngh gist delete abc123def"}}'

AUDITOOOR_NEVER_DELETE_GISTS_BYPASS=1 \
assert_allow "gap4-env-override: AUDITOOOR_NEVER_DELETE_GISTS_BYPASS=1" \
  '{"tool_name":"Bash","tool_input":{"command":"gh gist delete abc123def"}}'

# --- Gap 5: incrementNonce -------------------------------------------------

assert_deny "gap5-block: cast send incrementNonce" \
  '{"tool_name":"Bash","tool_input":{"command":"cast send 0xDEAD incrementNonce()"}}'

assert_allow "gap5-rebuttal: shell-comment rebuttal" \
  '{"tool_name":"Bash","tool_input":{"command":"# extreme-rebuttal-gap5-incrementNonce: operator-approved on test wallet only\ncast send 0xDEAD incrementNonce()"}}'

AUDITOOOR_NEVER_INCREMENTNONCE_BYPASS=1 \
assert_allow "gap5-env-override: AUDITOOOR_NEVER_INCREMENTNONCE_BYPASS=1" \
  '{"tool_name":"Bash","tool_input":{"command":"cast send 0xDEAD incrementNonce()"}}'

# --- Gap 6: raw git reset --hard NOT via wrapper ---------------------------

assert_deny "gap6-block: raw git reset --hard" \
  '{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~3"}}'

assert_allow "gap6-rebuttal: shell-comment rebuttal" \
  '{"tool_name":"Bash","tool_input":{"command":"# extreme-rebuttal-gap6-git-reset-hard-raw: solo lane, no sibling agents active\ngit reset --hard HEAD~3"}}'

AUDITOOOR_R55_RAW_RESET_BYPASS=1 \
assert_allow "gap6-env-override: AUDITOOOR_R55_RAW_RESET_BYPASS=1" \
  '{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~3"}}'

# Bonus: gap6 wrapper-invoked path is NOT classified as raw -> ALLOW
assert_allow "gap6-bonus: wrapper-invoked path allowed" \
  '{"tool_name":"Bash","tool_input":{"command":"bash tools/git-hooks/git-reset-safe.sh --hard HEAD~3"}}'

# Bonus: R55_REBUTTAL env (legacy override) still satisfies Gap 6
R55_REBUTTAL="solo lane operator-approved cleanup" \
assert_allow "gap6-bonus: legacy R55_REBUTTAL env" \
  '{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

total=$((pass + fail))
echo "==="
echo "PASS: $pass / $total"
if [ "$fail" -gt 0 ]; then
  echo "FAIL: $fail"
  for c in "${failed_cases[@]}"; do
    echo "  - $c"
  done
  rm -rf "$TMPDIR_TEST"
  exit 1
fi
rm -rf "$TMPDIR_TEST"
exit 0
