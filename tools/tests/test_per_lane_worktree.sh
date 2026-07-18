#!/usr/bin/env bash
# ============================================================================
# Shell-level tests for the per-lane git worktree provisioning + cleanup
# tools (PER-LANE-WORKTREE, 2026-05-23 Phase -1).
#
# Tests:
#   1. spawn-lane-worktree.sh provisions a worktree at the expected path
#   2. cleanup-lane-worktree.sh leaves an "ahead" worktree in place
#   3. cleanup-lane-worktree.sh removes a clean (no-edits) worktree
#   4. 5 concurrent spawn-lane-worktree.sh invocations all succeed without
#      cross-pollination
#   5. spawn-lane-worktree.sh with --register-pathspec registers the lane
#   6. cleanup-lane-worktree.sh with --unregister-pathspec drops the entry
#   7. lane-id validation rejects unsafe characters
#   8. JSON output emits the canonical schema
#   9. active vault_lane_cooldown_check blocks before worktree creation
#  10. audited cooldown bypass allows provisioning and logs the bypass
#
# Run: bash tools/tests/test_per_lane_worktree.sh
# ============================================================================

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Use real git binary, bypassing any operator wrapper.
GIT_BIN=""
for cand in /usr/bin/git /opt/homebrew/bin/git; do
  if [ -x "${cand}" ]; then
    GIT_BIN="${cand}"
    break
  fi
done
if [ -z "${GIT_BIN}" ]; then
  GIT_BIN="$(command -v git)"
fi
export PATH="$(dirname "${GIT_BIN}"):${PATH}"

SPAWN_TOOL="${REPO_ROOT}/tools/spawn-lane-worktree.sh"
CLEANUP_TOOL="${REPO_ROOT}/tools/cleanup-lane-worktree.sh"
PATHSPEC_TOOL="${REPO_ROOT}/tools/agent-pathspec-register.py"

if [ ! -x "${SPAWN_TOOL}" ]; then chmod +x "${SPAWN_TOOL}" 2>/dev/null || true; fi
if [ ! -x "${CLEANUP_TOOL}" ]; then chmod +x "${CLEANUP_TOOL}" 2>/dev/null || true; fi

TEST_TMP_BASE="$(mktemp -d -t plw-tests-XXXXXX)"
trap '_cleanup_all_test_repos' EXIT

# Track every repo + worktree we create so we can tear it all down.
declare -a TEST_REPOS=()
declare -a TEST_WORKTREES=()

_cleanup_all_test_repos() {
  for wt in "${TEST_WORKTREES[@]:-}"; do
    [ -n "${wt}" ] && rm -rf "${wt}" 2>/dev/null || true
  done
  for repo in "${TEST_REPOS[@]:-}"; do
    [ -n "${repo}" ] && rm -rf "${repo}" 2>/dev/null || true
  done
  rm -rf "${TEST_TMP_BASE}" 2>/dev/null || true
}

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
declare -a FAILED_NAMES=()

_pass() {
  local name="$1"
  TESTS_PASSED=$((TESTS_PASSED + 1))
  echo "  PASS: ${name}"
}
_fail() {
  local name="$1"; local why="$2"
  TESTS_FAILED=$((TESTS_FAILED + 1))
  FAILED_NAMES+=("${name}")
  echo "  FAIL: ${name}"
  echo "        ${why}"
}

# Build a throwaway repo with a copy of the spawn + cleanup tools mounted at
# tools/. The tools resolve REPO_ROOT relative to their own script dir, so
# they need to live inside the throwaway repo to bind to it.
_mk_test_repo() {
  local idx="$1"
  local repo="${TEST_TMP_BASE}/repo_${idx}"
  mkdir -p "${repo}/tools"
  TEST_REPOS+=("${repo}")

  pushd "${repo}" >/dev/null || return 1
  ${GIT_BIN} init -q -b main
  ${GIT_BIN} config user.email "test@example.com"
  ${GIT_BIN} config user.name "PLW Test"
  echo "seed" > seed.txt
  ${GIT_BIN} add seed.txt
  ${GIT_BIN} commit -q -m "seed" --no-verify 2>/dev/null || ${GIT_BIN} commit -q -m "seed"
  popd >/dev/null

  # Mount our 3 tools into the test repo so they resolve REPO_ROOT correctly.
  cp "${SPAWN_TOOL}"   "${repo}/tools/"
  cp "${CLEANUP_TOOL}" "${repo}/tools/"
  cp "${PATHSPEC_TOOL}" "${repo}/tools/" 2>/dev/null || true
  chmod +x "${repo}/tools/spawn-lane-worktree.sh" "${repo}/tools/cleanup-lane-worktree.sh"

  echo "${repo}"
}

_install_fake_cooldown_mcp() {
  local repo="$1"
  local verdict="$2"
  cat > "${repo}/tools/vault-mcp-server.py" <<PY
#!/usr/bin/env python3
import json
import sys

if "--call" not in sys.argv or "vault_lane_cooldown_check" not in sys.argv:
    print("fake MCP only supports vault_lane_cooldown_check", file=sys.stderr)
    sys.exit(2)

verdict = "${verdict}"
lanes = []
if verdict == "active-cooldown":
    lanes = [{
        "lane_id": "COOLED",
        "since_iter": 5,
        "reason": "synthetic cooldown for spawn-lane-worktree test",
        "current_iter": 7,
        "iter_age": 2,
        "staleness_class": "fresh",
    }]

print(json.dumps({
    "schema": "auditooor.vault_lane_cooldown_check.v1",
    "kind": "lane_cooldown",
    "verdict": verdict,
    "lanes": lanes,
    "total_cooldowns": len(lanes),
    "current_iter": 7,
    "state_file_status": "present",
    "state_file_path": "/tmp/fake-spark_hunt_loop_state.json",
    "context_pack_id": "auditooor.vault_lane_cooldown_check.v1:lane_cooldown:fake1234",
    "context_pack_hash": "fakehash",
}))
PY
  chmod +x "${repo}/tools/vault-mcp-server.py"
}

# ---------------------------------------------------------------------------
# Test 1: spawn-lane-worktree.sh provisions a worktree under default root
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T1_NAME="test1_spawn_provisions_worktree"
{
  REPO="$(_mk_test_repo 1)"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_1"
  mkdir -p "${WT_ROOT}"
  pushd "${REPO}" >/dev/null
  WT_PATH=$(bash tools/spawn-lane-worktree.sh \
             --lane-id "TEST1" \
             --worktree-root "${WT_ROOT}" 2>/dev/null)
  RC=$?
  popd >/dev/null
  TEST_WORKTREES+=("${WT_PATH}")
  if [ "${RC}" = "0" ] && [ -n "${WT_PATH}" ] && [ -d "${WT_PATH}" ]; then
    # Confirm naming convention
    case "${WT_PATH}" in
      ${WT_ROOT}/auditooor-lane-TEST1-*) _pass "${T1_NAME}" ;;
      *) _fail "${T1_NAME}" "unexpected wt path: ${WT_PATH}" ;;
    esac
  else
    _fail "${T1_NAME}" "rc=${RC} wt=${WT_PATH}"
  fi
}

# ---------------------------------------------------------------------------
# Test 2: cleanup-lane-worktree.sh leaves an "ahead" worktree alone
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T2_NAME="test2_cleanup_leaves_ahead_worktree"
{
  REPO="$(_mk_test_repo 2)"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_2"
  mkdir -p "${WT_ROOT}"
  pushd "${REPO}" >/dev/null
  WT_PATH=$(bash tools/spawn-lane-worktree.sh \
             --lane-id "TEST2" \
             --worktree-root "${WT_ROOT}" 2>/dev/null)
  popd >/dev/null
  TEST_WORKTREES+=("${WT_PATH}")
  # Make a commit in the worktree so it's ahead of base.
  pushd "${WT_PATH}" >/dev/null
  echo "ahead" > ahead.txt
  ${GIT_BIN} add ahead.txt
  ${GIT_BIN} commit -q -m "ahead" --no-verify 2>/dev/null || ${GIT_BIN} commit -q -m "ahead"
  popd >/dev/null

  pushd "${REPO}" >/dev/null
  VERDICT=$(bash tools/cleanup-lane-worktree.sh \
             --lane-id "TEST2" \
             --worktree-root "${WT_ROOT}" 2>/dev/null | head -1)
  popd >/dev/null
  if [ "${VERDICT}" = "ahead" ] && [ -d "${WT_PATH}" ]; then
    _pass "${T2_NAME}"
  else
    _fail "${T2_NAME}" "verdict=${VERDICT} wt_still_present=$([ -d "${WT_PATH}" ] && echo yes || echo no)"
  fi
}

# ---------------------------------------------------------------------------
# Test 3: cleanup-lane-worktree.sh removes a clean worktree
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T3_NAME="test3_cleanup_removes_clean_worktree"
{
  REPO="$(_mk_test_repo 3)"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_3"
  mkdir -p "${WT_ROOT}"
  pushd "${REPO}" >/dev/null
  WT_PATH=$(bash tools/spawn-lane-worktree.sh \
             --lane-id "TEST3" \
             --worktree-root "${WT_ROOT}" 2>/dev/null)
  popd >/dev/null
  TEST_WORKTREES+=("${WT_PATH}")
  # No edits; expect cleanup to remove.
  pushd "${REPO}" >/dev/null
  VERDICT=$(bash tools/cleanup-lane-worktree.sh \
             --lane-id "TEST3" \
             --worktree-root "${WT_ROOT}" 2>/dev/null | head -1)
  popd >/dev/null
  if [ "${VERDICT}" = "removed-clean" ] && [ ! -d "${WT_PATH}" ]; then
    _pass "${T3_NAME}"
  else
    _fail "${T3_NAME}" "verdict=${VERDICT} wt_still_present=$([ -d "${WT_PATH}" ] && echo yes || echo no)"
  fi
}

# ---------------------------------------------------------------------------
# Test 4: 5 concurrent spawn-lane-worktree.sh invocations - zero cross-pollination
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T4_NAME="test4_five_concurrent_spawns_no_cross_pollination"
{
  REPO="$(_mk_test_repo 4)"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_4"
  mkdir -p "${WT_ROOT}"
  PIDS=()
  RESULTS_DIR="${TEST_TMP_BASE}/results_4"
  mkdir -p "${RESULTS_DIR}"
  pushd "${REPO}" >/dev/null
  for i in 1 2 3 4 5; do
    (
      out=$(bash tools/spawn-lane-worktree.sh \
              --lane-id "CONCUR${i}" \
              --worktree-root "${WT_ROOT}" 2>/dev/null)
      rc=$?
      echo "${rc}:${out}" > "${RESULTS_DIR}/lane_${i}.txt"
    ) &
    PIDS+=("$!")
  done
  # Wait for all
  for pid in "${PIDS[@]}"; do
    wait "${pid}"
  done
  popd >/dev/null

  # Each lane should have its own worktree at a unique path; each must
  # be writeable + independent. Cross-pollination check: each worktree
  # creates a file with its own lane id; no two worktrees should see
  # each other's file.
  all_ok=1
  for i in 1 2 3 4 5; do
    line=$(cat "${RESULTS_DIR}/lane_${i}.txt")
    rc="${line%%:*}"
    wt="${line#*:}"
    if [ "${rc}" != "0" ] || [ -z "${wt}" ] || [ ! -d "${wt}" ]; then
      all_ok=0
      _fail "${T4_NAME}" "lane ${i} rc=${rc} wt=${wt}"
      break
    fi
    TEST_WORKTREES+=("${wt}")
    # Write a unique sentinel into each worktree
    echo "lane_${i}_only" > "${wt}/sentinel_${i}.txt"
  done

  if [ "${all_ok}" = "1" ]; then
    # Verify no cross-pollination: each worktree only sees its own sentinel
    for i in 1 2 3 4 5; do
      line=$(cat "${RESULTS_DIR}/lane_${i}.txt")
      wt="${line#*:}"
      # Count sentinel_*.txt files
      n=$(ls "${wt}"/sentinel_*.txt 2>/dev/null | wc -l | tr -d ' ')
      if [ "${n}" != "1" ]; then
        all_ok=0
        _fail "${T4_NAME}" "lane ${i} saw ${n} sentinels (expected 1) in ${wt}"
        break
      fi
    done
  fi

  if [ "${all_ok}" = "1" ]; then
    _pass "${T4_NAME}"
  fi
}

# ---------------------------------------------------------------------------
# Test 5: spawn with --register-pathspec registers the lane
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T5_NAME="test5_spawn_register_pathspec_records_lane"
{
  REPO="$(_mk_test_repo 5)"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_5"
  mkdir -p "${WT_ROOT}"
  pushd "${REPO}" >/dev/null
  WT_PATH=$(bash tools/spawn-lane-worktree.sh \
             --lane-id "TEST5" \
             --worktree-root "${WT_ROOT}" \
             --register-pathspec \
             --pathspec-files "tools/dummy.py" \
             2>/dev/null)
  popd >/dev/null
  TEST_WORKTREES+=("${WT_PATH}")
  PSFILE="${REPO}/.auditooor/agent_pathspec.json"
  if [ -f "${PSFILE}" ] && grep -q '"TEST5"' "${PSFILE}"; then
    _pass "${T5_NAME}"
  else
    _fail "${T5_NAME}" "pathspec entry not found at ${PSFILE}"
  fi
}

# ---------------------------------------------------------------------------
# Test 6: cleanup with --unregister-pathspec drops the entry
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T6_NAME="test6_cleanup_unregister_pathspec_drops_entry"
{
  REPO="$(_mk_test_repo 6)"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_6"
  mkdir -p "${WT_ROOT}"
  pushd "${REPO}" >/dev/null
  WT_PATH=$(bash tools/spawn-lane-worktree.sh \
             --lane-id "TEST6" \
             --worktree-root "${WT_ROOT}" \
             --register-pathspec \
             --pathspec-files "tools/dummy.py" \
             2>/dev/null)
  popd >/dev/null
  TEST_WORKTREES+=("${WT_PATH}")

  pushd "${REPO}" >/dev/null
  bash tools/cleanup-lane-worktree.sh \
       --lane-id "TEST6" \
       --worktree-root "${WT_ROOT}" \
       --unregister-pathspec \
       >/dev/null 2>&1
  popd >/dev/null

  PSFILE="${REPO}/.auditooor/agent_pathspec.json"
  if [ -f "${PSFILE}" ] && ! grep -q '"TEST6"' "${PSFILE}"; then
    _pass "${T6_NAME}"
  elif [ ! -f "${PSFILE}" ]; then
    # Empty pathspec file may have been removed.
    _pass "${T6_NAME}"
  else
    _fail "${T6_NAME}" "pathspec still has TEST6 entry"
  fi
}

# ---------------------------------------------------------------------------
# Test 7: lane-id validation rejects unsafe characters
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T7_NAME="test7_lane_id_validation_rejects_unsafe"
{
  REPO="$(_mk_test_repo 7)"
  pushd "${REPO}" >/dev/null
  bash tools/spawn-lane-worktree.sh \
       --lane-id "../escape" \
       --worktree-root "${TEST_TMP_BASE}/wt_root_7" \
       2>/dev/null
  RC=$?
  popd >/dev/null
  if [ "${RC}" != "0" ]; then
    _pass "${T7_NAME}"
  else
    _fail "${T7_NAME}" "expected non-zero rc for unsafe lane-id, got rc=${RC}"
  fi
}

# ---------------------------------------------------------------------------
# Test 8: --json output emits expected schema
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T8_NAME="test8_json_output_schema"
{
  REPO="$(_mk_test_repo 8)"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_8"
  mkdir -p "${WT_ROOT}"
  pushd "${REPO}" >/dev/null
  OUT=$(bash tools/spawn-lane-worktree.sh \
         --lane-id "TEST8" \
         --worktree-root "${WT_ROOT}" \
         --json 2>/dev/null)
  popd >/dev/null
  # Extract worktree_path from JSON to clean up
  WT_PATH=$(echo "${OUT}" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('worktree_path',''))" 2>/dev/null)
  TEST_WORKTREES+=("${WT_PATH}")
  SCHEMA=$(echo "${OUT}" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('schema',''))" 2>/dev/null)
  if [ "${SCHEMA}" = "auditooor.spawn_lane_worktree.v1" ] && [ -n "${WT_PATH}" ]; then
    _pass "${T8_NAME}"
  else
    _fail "${T8_NAME}" "schema=${SCHEMA} wt_path=${WT_PATH} out=${OUT}"
  fi
}

# ---------------------------------------------------------------------------
# Test 9: active cooldown blocks before creating a worktree
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T9_NAME="test9_active_cooldown_blocks_before_worktree_creation"
{
  REPO="$(_mk_test_repo 9)"
  _install_fake_cooldown_mcp "${REPO}" "active-cooldown"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_9"
  TARGET_WS="${REPO}/target-workspace"
  ERR_FILE="${TEST_TMP_BASE}/test9.stderr"
  mkdir -p "${WT_ROOT}" "${TARGET_WS}"
  pushd "${REPO}" >/dev/null
  OUT=$(bash tools/spawn-lane-worktree.sh \
         --lane-id "COOLED" \
         --workspace "${TARGET_WS}" \
         --worktree-root "${WT_ROOT}" \
         2>"${ERR_FILE}")
  RC=$?
  popd >/dev/null
  CREATED=$(find "${WT_ROOT}" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null)
  if [ "${RC}" = "6" ] && [ -z "${OUT}" ] && [ -z "${CREATED}" ] \
     && grep -q "active-cooldown" "${ERR_FILE}" \
     && grep -q "${TARGET_WS}" "${ERR_FILE}" \
     && grep -q "context_pack_id" "${ERR_FILE}"; then
    _pass "${T9_NAME}"
  else
    _fail "${T9_NAME}" "rc=${RC} out=${OUT} created=${CREATED} stderr=$(head -c 500 "${ERR_FILE}")"
  fi
}

# ---------------------------------------------------------------------------
# Test 10: explicit audited bypass allows provisioning despite active cooldown
# ---------------------------------------------------------------------------
TESTS_RUN=$((TESTS_RUN + 1))
T10_NAME="test10_audited_cooldown_bypass_allows_provisioning"
{
  REPO="$(_mk_test_repo 10)"
  _install_fake_cooldown_mcp "${REPO}" "active-cooldown"
  WT_ROOT="${TEST_TMP_BASE}/wt_root_10"
  ERR_FILE="${TEST_TMP_BASE}/test10.stderr"
  mkdir -p "${WT_ROOT}"
  pushd "${REPO}" >/dev/null
  WT_PATH=$(bash tools/spawn-lane-worktree.sh \
             --lane-id "COOLED_BYPASS" \
             --worktree-root "${WT_ROOT}" \
             --bypass-lane-cooldown-check \
             --bypass-lane-cooldown-reason "operator ticket TEST-10 trigger state changed" \
             2>"${ERR_FILE}")
  RC=$?
  popd >/dev/null
  TEST_WORKTREES+=("${WT_PATH}")
  if [ "${RC}" = "0" ] && [ -n "${WT_PATH}" ] && [ -d "${WT_PATH}" ] \
     && grep -q "AUDITED BYPASS" "${ERR_FILE}" \
     && grep -q "operator ticket TEST-10" "${ERR_FILE}"; then
    _pass "${T10_NAME}"
  else
    _fail "${T10_NAME}" "rc=${RC} wt=${WT_PATH} stderr=$(head -c 500 "${ERR_FILE}")"
  fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "==============================================="
echo "test_per_lane_worktree.sh summary"
echo "  run    : ${TESTS_RUN}"
echo "  passed : ${TESTS_PASSED}"
echo "  failed : ${TESTS_FAILED}"
if [ "${TESTS_FAILED}" -gt 0 ]; then
  echo "  failed names:"
  for n in "${FAILED_NAMES[@]:-}"; do
    echo "    - ${n}"
  done
  echo "==============================================="
  exit 1
fi
echo "==============================================="
exit 0
