#!/usr/bin/env bash
# ============================================================================
# Shell-level tests for tools/install-hooks.sh R36/R55 wiring.
#
# Complements tools/tests/test_install_hooks.py (which exercises hook content
# + install/uninstall/check subcommands). This file exercises the FIX-C
# integration story:
#
#   1. install on a bare temp repo (no bundled tools/git-hooks/) MUST NOT
#      set core.hooksPath to a missing directory (silent-skip with message)
#   2. install on the real auditooor-mcp workspace MUST set core.hooksPath
#      AND chain MCP + R36 in the generated pre-commit
#   3. The newly-generated pre-commit MUST invoke
#      pre-commit-pathspec-discipline.sh (R36) after the MCP check
#   4. dogfood subcommand exits 0 on the real workspace
#   5. print-aliases subcommand emits the 4 expected wrapper aliases
#   6. check subcommand reports R36 + R55 wrapper state
#   7. Two-lane sibling-pathspec violation test: installed pre-commit
#      REFUSES a commit that stages a sibling lane's file
#
# Run: bash tools/tests/test_install_hooks_r36_r55.sh
# ============================================================================

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_HOOKS="${REPO_ROOT}/tools/install-hooks.sh"

# Use the real /usr/bin/git instead of any operator-installed git wrapper.
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

SHIM_DIR="$(mktemp -d -t r36_r55_install_shim_XXXXXX)"
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

_assert_pass() {
    local name="$1"
    PASS=$((PASS+1))
    echo "  PASS: ${name}"
}

_assert_fail() {
    local name="$1"
    local why="$2"
    FAIL=$((FAIL+1))
    FAILED_NAMES="${FAILED_NAMES}\n  - ${name}: ${why}"
    echo "  FAIL: ${name}: ${why}" >&2
}

_isolated_repo() {
    local dir
    dir="$(mktemp -d -t r36_r55_install_XXXXXX)"
    (cd "${dir}" && "${GIT_BIN}" init -q && "${GIT_BIN}" config user.email t@t && "${GIT_BIN}" config user.name t)
    echo "${dir}"
}

# ---------------------------------------------------------------------------
# Test 1: install on bare temp repo must NOT corrupt core.hooksPath
# ---------------------------------------------------------------------------
test_1_install_bare_repo_silent_skip_hooks_path() {
    local name="test_1_install_bare_repo_silent_skip_hooks_path"
    local dir
    dir="$(_isolated_repo)"

    # Run install in the bare repo (no tools/git-hooks/ bundle present).
    AUDITOOOR_WS_ROOT="${dir}" AUDITOOOR_BIN_DIR="${dir}/.auditooor/bin" \
        bash "${INSTALL_HOOKS}" install >/dev/null 2>&1

    local actual
    actual="$("${GIT_BIN}" -C "${dir}" config --get core.hooksPath 2>/dev/null || echo '<unset>')"

    if [[ "${actual}" == "<unset>" ]] || [[ -z "${actual}" ]]; then
        _assert_pass "${name}: core.hooksPath stayed unset on bare repo"
    else
        _assert_fail "${name}" "core.hooksPath was set to '${actual}' but tools/git-hooks/ is missing"
    fi

    rm -rf "${dir}"
}

# ---------------------------------------------------------------------------
# Test 2: install on real workspace sets core.hooksPath
# ---------------------------------------------------------------------------
test_2_real_workspace_sets_hooks_path() {
    local name="test_2_real_workspace_sets_hooks_path"
    local actual
    actual="$("${GIT_BIN}" -C "${REPO_ROOT}" config --get core.hooksPath 2>/dev/null || echo '<unset>')"
    if [[ "${actual}" == "tools/git-hooks" ]]; then
        _assert_pass "${name}: core.hooksPath = '${actual}'"
    else
        _assert_fail "${name}" "core.hooksPath = '${actual}' (expected 'tools/git-hooks')"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: generated pre-commit invokes the R36 hook
# ---------------------------------------------------------------------------
test_3_pre_commit_chains_r36() {
    local name="test_3_pre_commit_chains_r36"
    local pc="${REPO_ROOT}/tools/git-hooks/pre-commit"
    if [[ ! -f "${pc}" ]]; then
        _assert_fail "${name}" "pre-commit hook missing at ${pc}"
        return
    fi
    if grep -q "pre-commit-pathspec-discipline.sh" "${pc}"; then
        _assert_pass "${name}: pre-commit references pre-commit-pathspec-discipline.sh"
    else
        _assert_fail "${name}" "pre-commit does NOT reference pre-commit-pathspec-discipline.sh"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: dogfood subcommand exits 0 on real workspace
# ---------------------------------------------------------------------------
test_4_dogfood_exits_zero_on_real_workspace() {
    local name="test_4_dogfood_exits_zero_on_real_workspace"
    local out rc
    out="$(bash "${INSTALL_HOOKS}" dogfood 2>&1)" && rc=$? || rc=$?
    if [[ "${rc}" == "0" ]] && echo "${out}" | grep -q "dogfood] PASS"; then
        _assert_pass "${name}: dogfood rc=0 and PASS marker present"
    else
        _assert_fail "${name}" "dogfood rc=${rc}; output:\n${out}"
    fi
}

# ---------------------------------------------------------------------------
# Test 5: print-aliases emits 4 wrapper aliases
# ---------------------------------------------------------------------------
test_5_print_aliases_emits_four_wrappers() {
    local name="test_5_print_aliases_emits_four_wrappers"
    local out
    out="$(bash "${INSTALL_HOOKS}" print-aliases 2>&1)"
    local count=0
    for wrapper in git-reset-safe.sh git-checkout-safe.sh git-clean-safe.sh git-stash-safe.sh; do
        if echo "${out}" | grep -q "${wrapper}"; then
            count=$((count+1))
        fi
    done
    if [[ "${count}" -eq 4 ]]; then
        _assert_pass "${name}: all 4 wrapper aliases present"
    else
        _assert_fail "${name}" "only ${count}/4 wrapper aliases in output"
    fi
}

# ---------------------------------------------------------------------------
# Test 6: check subcommand reports R36 + R55 wrapper state
# ---------------------------------------------------------------------------
test_6_check_reports_r36_r55_state() {
    local name="test_6_check_reports_r36_r55_state"
    local out
    out="$(bash "${INSTALL_HOOKS}" check 2>&1)"
    if echo "${out}" | grep -q "R36 hook:" && echo "${out}" | grep -q "R55 gate script:"; then
        _assert_pass "${name}: check reports both R36 and R55 state"
    else
        _assert_fail "${name}" "check output missing R36 or R55 state line; output:\n${out}"
    fi
}

# ---------------------------------------------------------------------------
# Test 7: installed pre-commit refuses sibling-pathspec violation
# ---------------------------------------------------------------------------
test_7_pre_commit_refuses_sibling_violation() {
    local name="test_7_pre_commit_refuses_sibling_violation"
    local dir
    dir="$(_isolated_repo)"

    # Stage the canonical hooks scripts into the temp repo and run our
    # generated pre-commit (chained version) directly against it.
    mkdir -p "${dir}/tools/git-hooks" "${dir}/.auditooor"
    cp "${REPO_ROOT}/tools/git-hooks/pre-commit-pathspec-discipline.sh" "${dir}/tools/git-hooks/"
    chmod +x "${dir}/tools/git-hooks/pre-commit-pathspec-discipline.sh"

    # Generate the chained pre-commit into the temp repo (use AUDITOOOR_WS_ROOT
    # to keep install-hooks isolated).
    AUDITOOOR_WS_ROOT="${dir}" AUDITOOOR_BIN_DIR="${dir}/.auditooor/bin" \
        AUDITOOOR_SKIP_HOOKS_PATH=1 \
        bash "${INSTALL_HOOKS}" install >/dev/null 2>&1

    # Write a two-lane pathspec. lane-A owns foo.py; lane-B owns bar.py.
    cat > "${dir}/.auditooor/agent_pathspec.json" <<EOF
{
  "agents": [
    {"agent_id": "lane-A", "files": ["foo.py"], "expires_at": "2099-12-31T00:00:00Z"},
    {"agent_id": "lane-B", "files": ["bar.py"], "expires_at": "2099-12-31T00:00:00Z"}
  ]
}
EOF

    # Create + stage bar.py from lane-A's perspective (sibling violation).
    (cd "${dir}" && echo "lane-A content" > bar.py && "${GIT_BIN}" add bar.py)

    # Invoke the installed pre-commit as lane-A. Should be REFUSED by R36.
    # IMPORTANT: cd into the temp repo before invoking the hook, otherwise
    # `git rev-parse --show-toplevel` inside the hook returns the wrong root
    # (the cwd of the parent shell, not the temp repo). AUDITOOOR_WS_ROOT
    # does not help here because the R36 sub-hook resolves the repo via
    # `git rev-parse --show-toplevel` independently.
    local hook_path="${dir}/.git/hooks/pre-commit"
    local out rc
    out="$(cd "${dir}" && AUDITOOOR_WS_ROOT="${dir}" AUDITOOOR_MCP_REQUIRED=0 \
        R36_CURRENT_AGENT_ID=lane-A \
        bash "${hook_path}" 2>&1)" && rc=$? || rc=$?

    if [[ "${rc}" != "0" ]] && echo "${out}" | grep -q "r36-pathspec.*REFUSED"; then
        _assert_pass "${name}: pre-commit chain refused sibling violation (rc=${rc})"
    else
        _assert_fail "${name}" "expected REFUSED with rc!=0; got rc=${rc}, out:\n${out}"
    fi

    rm -rf "${dir}"
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
echo "Running install-hooks R36/R55 wiring shell tests..."
echo ""

test_1_install_bare_repo_silent_skip_hooks_path
test_2_real_workspace_sets_hooks_path
test_3_pre_commit_chains_r36
test_4_dogfood_exits_zero_on_real_workspace
test_5_print_aliases_emits_four_wrappers
test_6_check_reports_r36_r55_state
test_7_pre_commit_refuses_sibling_violation

echo ""
echo "Results: ${PASS} pass / ${FAIL} fail"
if [[ "${FAIL}" -gt 0 ]]; then
    echo -e "Failures:${FAILED_NAMES}" >&2
    exit 1
fi
exit 0
