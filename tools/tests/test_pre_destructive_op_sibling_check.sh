#!/usr/bin/env bash
# ============================================================================
# Shell-level tests for the Rule 55 destructive-op gate, exercising each
# destructive-op pathway end-to-end via the wrapper scripts (not just
# the underlying hook). This complements the Python unit tests in
# tools/tests/test_pre_destructive_op_sibling_check.py which exercise the
# hook directly with controlled env vars.
#
# Pathways tested at wrapper level:
#   1. git-reset-safe.sh --hard HEAD ........ refused on sibling-owned WT edit
#   2. git-reset-safe.sh --soft HEAD~0 ...... passes (no WT mutation)
#   3. git-checkout-safe.sh -- <path> ....... refused on sibling-owned WT edit
#   4. git-checkout-safe.sh -- <path> ....... passes when R55_REBUTTAL set
#   5. git-clean-safe.sh -fd ................ refused on sibling-owned tracked edit
#   6. git-stash-safe.sh drop stash@{0} ..... refused on sibling-owned WT edit
#   7. git-stash-safe.sh push -m foo -- ..... passes (push is non-destructive)
#   8. git-stash-safe.sh apply stash@{0} .... passes (apply is restorative)
#
# Each test builds an isolated repo, registers two lanes in
# .auditooor/agent_pathspec.json, modifies a sibling-lane-owned file, then
# invokes the wrapper and asserts the expected exit code + stdout marker.
#
# Run: bash tools/tests/test_pre_destructive_op_sibling_check.sh
# ============================================================================

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WRAPPERS="${REPO_ROOT}/tools/git-hooks"

# Use the real /usr/bin/git instead of any operator-installed git wrapper
# (e.g. auditooor's MCP-recall enforcement wrapper at
# ~/.auditooor/bin/git) which would reject every invocation in the
# throwaway repos this test creates.
GIT_BIN=""
for cand in /usr/bin/git /opt/homebrew/bin/git; do
  if [ -x "${cand}" ]; then
    GIT_BIN="${cand}"
    break
  fi
done
if [ -z "${GIT_BIN}" ]; then
  GIT_BIN="$(command -v git || echo git)"
fi

# Create a PATH-prefix shim directory that re-exports `git` to the real
# binary. Wrapper scripts use `exec git` which goes through PATH, so a
# shell function won't suffice - we need a real executable on disk.
SHIM_DIR="$(mktemp -d -t r55_git_shim_XXXXXX)"
cat > "${SHIM_DIR}/git" <<EOF
#!/usr/bin/env bash
exec "${GIT_BIN}" "\$@"
EOF
chmod +x "${SHIM_DIR}/git"
export PATH="${SHIM_DIR}:${PATH}"
trap 'rm -rf "${SHIM_DIR}"' EXIT

PASS=0
FAIL=0
FAILED_NAMES=""

_log_pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
_log_fail() {
  FAIL=$((FAIL + 1))
  FAILED_NAMES="${FAILED_NAMES}    - $1
"
  echo "  FAIL: $1"
}

_setup_repo() {
  # Create a fresh git repo with seed.txt committed, register two lanes
  # (lane-CURRENT, lane-SIBLING), and stage a sibling-owned modification.
  TMP="$(mktemp -d -t r55_wrapper_XXXXXX)"
  cd "${TMP}"
  git init -q .
  git config user.email "test@example.com"
  git config user.name "Test"
  echo "seed" > seed.txt
  git add seed.txt
  git commit -q -m "seed"

  mkdir -p tools agent_briefs .auditooor
  echo "initial" > tools/foo.py
  echo "initial" > agent_briefs/sibling_brief.md
  git add tools/foo.py agent_briefs/sibling_brief.md
  git commit -q -m "add lane-owned files"

  # Future TTL (2 hours out).
  FUTURE="$(date -u -v +2H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
            date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)"

  cat > .auditooor/agent_pathspec.json <<EOF
{
  "agents": [
    {
      "agent_id": "lane-CURRENT",
      "files": ["tools/foo.py"],
      "expires_at": "${FUTURE}"
    },
    {
      "agent_id": "lane-SIBLING",
      "files": ["agent_briefs/sibling_brief.md"],
      "expires_at": "${FUTURE}"
    }
  ]
}
EOF

  # Modify the sibling-owned file to make it appear in `git status -uno`.
  echo "modified" > agent_briefs/sibling_brief.md
}

_teardown_repo() {
  cd /
  rm -rf "${TMP}"
}

# ---------------------------------------------------------------------------
# Test 1: git-reset-safe.sh --hard HEAD against sibling-owned WT edit -> FAIL
# ---------------------------------------------------------------------------
test_reset_hard_refused_on_sibling_edit() {
  _setup_repo
  local rc=0
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  bash "${WRAPPERS}/git-reset-safe.sh" --hard HEAD > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -ne 0 ] && grep -q "REFUSED" /tmp/r55_test_out; then
    _log_pass "test_reset_hard_refused_on_sibling_edit"
  else
    _log_fail "test_reset_hard_refused_on_sibling_edit (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
# Test 2: git-reset-safe.sh --soft is a no-op (no WT mutation)
# ---------------------------------------------------------------------------
test_reset_soft_passes() {
  _setup_repo
  local rc=0
  # `--soft` to current HEAD is a no-op against the WT; gate must short-circuit
  # without touching git (no commit-target needed).
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  WRAPPER_OP=reset \
  WRAPPER_ARGS="--soft" \
  bash "${WRAPPERS}/pre-destructive-op-sibling-check.sh" > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -eq 0 ]; then
    _log_pass "test_reset_soft_passes"
  else
    _log_fail "test_reset_soft_passes (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
# Test 3: git-checkout-safe.sh -- <sibling-path> -> FAIL on sibling-owned edit
# ---------------------------------------------------------------------------
test_checkout_file_revert_refused_on_sibling_edit() {
  _setup_repo
  local rc=0
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  bash "${WRAPPERS}/git-checkout-safe.sh" -- agent_briefs/sibling_brief.md > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -ne 0 ] && grep -q "REFUSED" /tmp/r55_test_out; then
    _log_pass "test_checkout_file_revert_refused_on_sibling_edit"
  else
    _log_fail "test_checkout_file_revert_refused_on_sibling_edit (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
# Test 4: git-checkout-safe.sh with R55_REBUTTAL env override -> passes
# ---------------------------------------------------------------------------
test_checkout_with_rebuttal_passes() {
  _setup_repo
  local rc=0
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  R55_REBUTTAL="operator authorized rollback per FIX-B audit" \
  bash "${WRAPPERS}/git-checkout-safe.sh" -- agent_briefs/sibling_brief.md > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -eq 0 ] && grep -q "rebuttal accepted" /tmp/r55_test_out; then
    _log_pass "test_checkout_with_rebuttal_passes"
  else
    _log_fail "test_checkout_with_rebuttal_passes (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
# Test 5: git-clean-safe.sh -fd on a repo with sibling-tracked-edit -> FAIL
# (clean does not actually touch tracked-modified files, but the gate fires
# on the precondition that sibling WT work is uncommitted; this catches the
# co-occurrence misclassification case)
# ---------------------------------------------------------------------------
test_clean_refused_when_sibling_tracked_edit_present() {
  _setup_repo
  local rc=0
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  bash "${WRAPPERS}/git-clean-safe.sh" -fd > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -ne 0 ] && grep -q "REFUSED" /tmp/r55_test_out; then
    _log_pass "test_clean_refused_when_sibling_tracked_edit_present"
  else
    _log_fail "test_clean_refused_when_sibling_tracked_edit_present (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
# Test 6: git-stash-safe.sh drop with sibling-owned WT edit -> FAIL
# ---------------------------------------------------------------------------
test_stash_drop_refused_on_sibling_edit() {
  _setup_repo
  # Create a stash entry first (using the lane-CURRENT-owned file).
  echo "current-edit" > tools/foo.py
  git stash push -m "current-rescue" -- tools/foo.py > /dev/null 2>&1
  # Sibling-edit still in place (we re-write because stash push moved it).
  echo "modified" > agent_briefs/sibling_brief.md
  local rc=0
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  bash "${WRAPPERS}/git-stash-safe.sh" drop stash@{0} > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -ne 0 ] && grep -q "REFUSED" /tmp/r55_test_out; then
    _log_pass "test_stash_drop_refused_on_sibling_edit"
  else
    _log_fail "test_stash_drop_refused_on_sibling_edit (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
# Test 7: git-stash-safe.sh push (non-destructive) -> passes
# ---------------------------------------------------------------------------
test_stash_push_passes() {
  _setup_repo
  local rc=0
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  bash "${WRAPPERS}/git-stash-safe.sh" push -m current-rescue -- tools/foo.py > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -eq 0 ]; then
    _log_pass "test_stash_push_passes"
  else
    _log_fail "test_stash_push_passes (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
# Test 8: git-stash-safe.sh apply (restorative) -> passes
# ---------------------------------------------------------------------------
test_stash_apply_passes() {
  _setup_repo
  echo "current-edit" > tools/foo.py
  git stash push -m "current-rescue" -- tools/foo.py > /dev/null 2>&1
  local rc=0
  R55_CURRENT_AGENT_ID=lane-CURRENT \
  bash "${WRAPPERS}/git-stash-safe.sh" apply stash@{0} > /tmp/r55_test_out 2>&1 || rc=$?
  if [ "${rc}" -eq 0 ]; then
    _log_pass "test_stash_apply_passes"
  else
    _log_fail "test_stash_apply_passes (rc=${rc})"
    cat /tmp/r55_test_out | head -10
  fi
  _teardown_repo
}

# ---------------------------------------------------------------------------
echo "Running R55 destructive-op wrapper test suite..."
echo
test_reset_hard_refused_on_sibling_edit
test_reset_soft_passes
test_checkout_file_revert_refused_on_sibling_edit
test_checkout_with_rebuttal_passes
test_clean_refused_when_sibling_tracked_edit_present
test_stash_drop_refused_on_sibling_edit
test_stash_push_passes
test_stash_apply_passes

echo
echo "================================"
echo "Total: $((PASS + FAIL)) tests, ${PASS} passed, ${FAIL} failed"
echo "================================"
if [ "${FAIL}" -gt 0 ]; then
  echo "Failed tests:"
  echo "${FAILED_NAMES}"
  exit 1
fi
exit 0
