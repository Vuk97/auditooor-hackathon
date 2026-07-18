#!/usr/bin/env bash
# ============================================================================
# Tests for tools/cleanup-lane-worktree.sh unmerged-commits refusal +
# --force-unmerged override (LANE-INTEGRATOR-AUTOMERGE-PATCH, 2026-05-23).
#
# Companion to tools/tests/test_per_lane_worktree.sh which covers the
# pre-existing dirty / ahead / clean-removal paths. This file focuses on
# the NEW behaviour added by LANE-INTEGRATOR-AUTOMERGE-PATCH:
#   1. All-merged worktree passes (removed-clean).
#   2. Unmerged worktree refused with verdict=unmerged.
#   3. --force-unmerged overrides the refusal and removes the worktree.
#   4. Idempotent cleanup: re-running on absent worktree is a no-op
#      (verdict=already-absent), preserving existing behaviour.
#
# Run: bash tools/tests/test_cleanup_lane_worktree.sh
# Exit 0 = all pass; non-zero = at least one fail.
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Use real git binary, bypass any operator wrapper.
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

TEST_TMP_BASE="$(mktemp -d -t clw-tests-XXXXXX)"
declare -a TEST_DIRS=()

_teardown() {
    for d in "${TEST_DIRS[@]:-}"; do
        [ -n "${d}" ] && rm -rf "${d}" 2>/dev/null || true
    done
    rm -rf "${TEST_TMP_BASE}" 2>/dev/null || true
}
trap _teardown EXIT

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

# ----------------------------------------------------------------------------
# Build a throwaway repo with the cleanup tool mounted at tools/. The tool
# resolves REPO_ROOT relative to its own script dir, so it needs to live
# inside the throwaway repo to bind to it. We also seed a bare upstream so
# the unmerged-commits check has an `origin/main` to evaluate.
# ----------------------------------------------------------------------------
_mk_test_repo_with_upstream() {
    local idx="$1"
    local upstream="${TEST_TMP_BASE}/upstream_${idx}.git"
    local repo="${TEST_TMP_BASE}/repo_${idx}"
    TEST_DIRS+=("${upstream}" "${repo}")

    mkdir -p "${repo}/tools"

    ${GIT_BIN} init -q --bare -b main "${upstream}" 2>/dev/null \
        || ${GIT_BIN} init -q --bare "${upstream}"

    pushd "${repo}" >/dev/null || return 1
    ${GIT_BIN} init -q -b main 2>/dev/null || ${GIT_BIN} init -q
    ${GIT_BIN} config user.email "test@example.com"
    ${GIT_BIN} config user.name  "CLW Test"
    ${GIT_BIN} remote add origin "${upstream}"
    echo "seed" > seed.txt
    ${GIT_BIN} add seed.txt
    ${GIT_BIN} commit -q -m "seed"
    ${GIT_BIN} branch -M main 2>/dev/null || true
    ${GIT_BIN} push -q -u origin main
    popd >/dev/null

    cp "${SPAWN_TOOL}"   "${repo}/tools/"
    cp "${CLEANUP_TOOL}" "${repo}/tools/"
    cp "${REPO_ROOT}/tools/agent-pathspec-register.py" \
       "${repo}/tools/" 2>/dev/null || true
    chmod +x "${repo}/tools/spawn-lane-worktree.sh" \
             "${repo}/tools/cleanup-lane-worktree.sh"

    echo "${repo}"
}

# ----------------------------------------------------------------------------
# Test 1: all-merged worktree passes (verdict=removed-clean).
# Setup: spawn a lane worktree, do not commit anything, then run cleanup.
# Expectation: cleanup removes the worktree and emits removed-clean.
# ----------------------------------------------------------------------------
test_01_all_merged_passes() {
    local name="01_all_merged_passes"
    TESTS_RUN=$((TESTS_RUN + 1))
    local repo
    repo="$(_mk_test_repo_with_upstream "01")"
    local wt_root="${TEST_TMP_BASE}/wt_01"
    mkdir -p "${wt_root}"

    pushd "${repo}" >/dev/null
    bash tools/spawn-lane-worktree.sh \
        --lane-id "TEST-CLEAN" \
        --base-branch main \
        --worktree-root "${wt_root}" >/dev/null 2>&1
    local rc=$?
    if [ ${rc} -ne 0 ]; then
        popd >/dev/null
        _fail "${name}" "spawn-lane-worktree.sh exited rc=${rc}"
        return
    fi

    # Run cleanup; expect removed-clean
    local out
    out=$(bash tools/cleanup-lane-worktree.sh \
        --lane-id "TEST-CLEAN" \
        --base-branch main \
        --worktree-root "${wt_root}" 2>/dev/null | head -1)
    popd >/dev/null

    if [ "${out}" = "removed-clean" ]; then
        _pass "${name}"
    else
        _fail "${name}" "expected verdict=removed-clean, got: ${out}"
    fi
}

# ----------------------------------------------------------------------------
# Test 2: unmerged worktree refuses with verdict=unmerged.
# Setup: spawn a lane worktree, commit a file in the worktree (not pushed,
# not merged to main). Run cleanup without --force / --force-unmerged.
# Expectation: cleanup refuses with verdict=unmerged.
# ----------------------------------------------------------------------------
test_02_unmerged_refuses() {
    local name="02_unmerged_refuses"
    TESTS_RUN=$((TESTS_RUN + 1))
    local repo
    repo="$(_mk_test_repo_with_upstream "02")"
    local wt_root="${TEST_TMP_BASE}/wt_02"
    mkdir -p "${wt_root}"

    pushd "${repo}" >/dev/null
    bash tools/spawn-lane-worktree.sh \
        --lane-id "TEST-UNMERGED" \
        --base-branch main \
        --worktree-root "${wt_root}" >/dev/null 2>&1
    local rc=$?
    if [ ${rc} -ne 0 ]; then
        popd >/dev/null
        _fail "${name}" "spawn-lane-worktree.sh exited rc=${rc}"
        return
    fi

    # Find the worktree path created by spawn and commit a file in it
    local wt_path
    wt_path="$(ls -d "${wt_root}/auditooor-lane-TEST-UNMERGED-"* 2>/dev/null | head -1)"
    if [ -z "${wt_path}" ] || [ ! -d "${wt_path}" ]; then
        popd >/dev/null
        _fail "${name}" "spawn did not create worktree under ${wt_root}"
        return
    fi
    echo "unmerged work" > "${wt_path}/unmerged.txt"
    ${GIT_BIN} -C "${wt_path}" add unmerged.txt
    ${GIT_BIN} -C "${wt_path}" commit -q -m "lane: unmerged work" 2>/dev/null

    # Run cleanup; expect verdict=unmerged (NOT removed)
    local out
    out=$(bash tools/cleanup-lane-worktree.sh \
        --lane-id "TEST-UNMERGED" \
        --base-branch main \
        --worktree-root "${wt_root}" 2>/dev/null | head -1)
    popd >/dev/null

    # The worktree should still exist after the refusal.
    if [ "${out}" = "unmerged" ] && [ -d "${wt_path}" ]; then
        _pass "${name}"
    else
        _fail "${name}" \
              "expected verdict=unmerged + worktree intact; got verdict=${out} wt_exists=$( [ -d "${wt_path}" ] && echo yes || echo no )"
    fi
}

# ----------------------------------------------------------------------------
# Test 3: --force-unmerged removes the worktree despite unmerged commits.
# Setup: same as test 2, but pass --force-unmerged.
# Expectation: cleanup removes the worktree with verdict=removed-clean.
# ----------------------------------------------------------------------------
test_03_force_unmerged_overrides() {
    local name="03_force_unmerged_overrides"
    TESTS_RUN=$((TESTS_RUN + 1))
    local repo
    repo="$(_mk_test_repo_with_upstream "03")"
    local wt_root="${TEST_TMP_BASE}/wt_03"
    mkdir -p "${wt_root}"

    pushd "${repo}" >/dev/null
    bash tools/spawn-lane-worktree.sh \
        --lane-id "TEST-FORCE" \
        --base-branch main \
        --worktree-root "${wt_root}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        popd >/dev/null
        _fail "${name}" "spawn-lane-worktree.sh failed"
        return
    fi

    local wt_path
    wt_path="$(ls -d "${wt_root}/auditooor-lane-TEST-FORCE-"* 2>/dev/null | head -1)"
    if [ -z "${wt_path}" ] || [ ! -d "${wt_path}" ]; then
        popd >/dev/null
        _fail "${name}" "spawn did not create worktree"
        return
    fi
    echo "force me" > "${wt_path}/force.txt"
    ${GIT_BIN} -C "${wt_path}" add force.txt
    ${GIT_BIN} -C "${wt_path}" commit -q -m "lane: force-unmerged target"

    # First confirm refusal without --force-unmerged
    local out_refuse
    out_refuse=$(bash tools/cleanup-lane-worktree.sh \
        --lane-id "TEST-FORCE" \
        --base-branch main \
        --worktree-root "${wt_root}" 2>/dev/null | head -1)

    # Now pass --force-unmerged
    local out_force
    out_force=$(bash tools/cleanup-lane-worktree.sh \
        --lane-id "TEST-FORCE" \
        --base-branch main \
        --worktree-root "${wt_root}" \
        --force-unmerged 2>/dev/null | head -1)
    popd >/dev/null

    if [ "${out_refuse}" = "unmerged" ] \
       && [ "${out_force}" = "removed-clean" ] \
       && [ ! -d "${wt_path}" ]; then
        _pass "${name}"
    else
        _fail "${name}" \
              "expected refuse=unmerged then force=removed-clean + wt absent; got refuse=${out_refuse} force=${out_force} wt_exists=$( [ -d "${wt_path}" ] && echo yes || echo no )"
    fi
}

# ----------------------------------------------------------------------------
# Test 4: idempotent cleanup (re-run on an absent worktree is a no-op).
# Setup: spawn, cleanup (clean), then cleanup again.
# Expectation: second cleanup emits verdict=already-absent.
# ----------------------------------------------------------------------------
test_04_idempotent_cleanup() {
    local name="04_idempotent_cleanup"
    TESTS_RUN=$((TESTS_RUN + 1))
    local repo
    repo="$(_mk_test_repo_with_upstream "04")"
    local wt_root="${TEST_TMP_BASE}/wt_04"
    mkdir -p "${wt_root}"

    pushd "${repo}" >/dev/null
    bash tools/spawn-lane-worktree.sh \
        --lane-id "TEST-IDEM" \
        --base-branch main \
        --worktree-root "${wt_root}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        popd >/dev/null
        _fail "${name}" "spawn-lane-worktree.sh failed"
        return
    fi

    local out_first
    out_first=$(bash tools/cleanup-lane-worktree.sh \
        --lane-id "TEST-IDEM" \
        --base-branch main \
        --worktree-root "${wt_root}" 2>/dev/null | head -1)

    local out_second
    out_second=$(bash tools/cleanup-lane-worktree.sh \
        --lane-id "TEST-IDEM" \
        --base-branch main \
        --worktree-root "${wt_root}" 2>/dev/null | head -1)
    popd >/dev/null

    if [ "${out_first}" = "removed-clean" ] \
       && [ "${out_second}" = "already-absent" ]; then
        _pass "${name}"
    else
        _fail "${name}" \
              "expected first=removed-clean then second=already-absent; got first=${out_first} second=${out_second}"
    fi
}

# ----------------------------------------------------------------------------
# Run all tests
# ----------------------------------------------------------------------------
echo "test_cleanup_lane_worktree.sh starting..."
echo "  repo_root=${REPO_ROOT}"
echo "  cleanup_tool=${CLEANUP_TOOL}"
echo "  tmp_base=${TEST_TMP_BASE}"
echo ""

test_01_all_merged_passes
test_02_unmerged_refuses
test_03_force_unmerged_overrides
test_04_idempotent_cleanup

echo ""
echo "Run summary:"
echo "  total = ${TESTS_RUN}"
echo "  pass  = ${TESTS_PASSED}"
echo "  fail  = ${TESTS_FAILED}"
if [ ${TESTS_FAILED} -gt 0 ]; then
    echo "  failed names:"
    for n in "${FAILED_NAMES[@]}"; do
        echo "    - ${n}"
    done
    exit 1
fi
exit 0
