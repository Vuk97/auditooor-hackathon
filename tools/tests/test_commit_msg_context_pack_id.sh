#!/usr/bin/env bash
# tests/test_commit_msg_context_pack_id.sh
# 6 tests for the commit-msg hook context_pack_id enforcement.
# Run: bash tools/tests/test_commit_msg_context_pack_id.sh
# All tests must report PASS.

set -euo pipefail

HOOK="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/git-hooks/commit-msg"

# We need a fake git repo for WS_ROOT resolution
TMPDIR_BASE="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_BASE"' EXIT

# Create a minimal fake git repo so 'git rev-parse --show-toplevel' works
FAKE_REPO="$TMPDIR_BASE/repo"
mkdir -p "$FAKE_REPO"
git -C "$FAKE_REPO" init -q
export AUDITOOOR_WS_ROOT="$FAKE_REPO"

PASS_COUNT=0
FAIL_COUNT=0

_run_test() {
    local num="$1"
    local desc="$2"
    local msg_content="$3"
    local expected_exit="$4"
    shift 4
    local env_vars=("$@")

    # Write commit message to temp file
    local msg_file
    msg_file="$(mktemp "$TMPDIR_BASE/commit_msg_XXXXXX")"
    printf '%s' "$msg_content" > "$msg_file"

    # Build env prefix
    local env_prefix=""
    for ev in "${env_vars[@]+"${env_vars[@]}"}"; do
        env_prefix="$env_prefix $ev"
    done

    # Run the hook
    local actual_exit=0
    if [[ -n "$env_prefix" ]]; then
        eval "env $env_prefix bash \"$HOOK\" \"$msg_file\" >/dev/null 2>&1" || actual_exit=$?
    else
        bash "$HOOK" "$msg_file" >/dev/null 2>&1 || actual_exit=$?
    fi

    if [[ "$actual_exit" == "$expected_exit" ]]; then
        echo "PASS test-$num: $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL test-$num: $desc (expected exit $expected_exit, got $actual_exit)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    rm -f "$msg_file"
}

# Also test that the refusal message says REFUSED (not just WARN)
_run_test_with_output() {
    local num="$1"
    local desc="$2"
    local msg_content="$3"
    local expected_exit="$4"
    local expected_pattern="$5"

    local msg_file
    msg_file="$(mktemp "$TMPDIR_BASE/commit_msg_XXXXXX")"
    printf '%s' "$msg_content" > "$msg_file"

    local actual_exit=0
    local output
    output="$(bash "$HOOK" "$msg_file" 2>&1)" || actual_exit=$?

    local status_ok=0
    local pattern_ok=0

    [[ "$actual_exit" == "$expected_exit" ]] && status_ok=1
    echo "$output" | grep -qiE "$expected_pattern" && pattern_ok=1

    if [[ "$status_ok" == "1" && "$pattern_ok" == "1" ]]; then
        echo "PASS test-$num: $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL test-$num: $desc"
        [[ "$status_ok" != "1" ]] && echo "  exit: expected $expected_exit, got $actual_exit"
        [[ "$pattern_ok" != "1" ]] && echo "  output pattern '$expected_pattern' not found in: $output"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    rm -f "$msg_file"
}

# ---------------------------------------------------------------------------
# Test 1: commit with context_pack_id passes (exit 0)
# ---------------------------------------------------------------------------
_run_test 1 \
    "commit with context_pack_id passes" \
    "Fix thing

context_pack_id: auditooor.vault_resume_context.v1:resume:abc1234567890def

Co-Authored-By: Test <test@example.com>" \
    0

# ---------------------------------------------------------------------------
# Test 2: commit without context_pack_id is REFUSED (exit 1) with actionable message
# ---------------------------------------------------------------------------
_run_test_with_output 2 \
    "commit without context_pack_id is REFUSED with actionable message" \
    "Fix thing

This is a commit without any pack ID.

Co-Authored-By: Test <test@example.com>" \
    1 \
    "REFUSED"

# ---------------------------------------------------------------------------
# Test 3: bypass envvar AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID=1 allows commit (exit 0)
# ---------------------------------------------------------------------------
_run_test 3 \
    "AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID=1 allows commit" \
    "Fix thing

No pack ID here intentionally.

Co-Authored-By: Test <test@example.com>" \
    0 \
    "AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID=1"

# ---------------------------------------------------------------------------
# Test 4: rebuttal pattern with valid reason allows commit (exit 0)
# ---------------------------------------------------------------------------
_run_test 4 \
    "valid commit-msg-rebuttal marker allows commit" \
    "Fix thing

No pack ID - auto-integrator commit with embedded pack.

<!-- commit-msg-rebuttal: lane-integrator auto-commit; pack embedded in lane state file -->

Co-Authored-By: Test <test@example.com>" \
    0

# ---------------------------------------------------------------------------
# Test 5: empty rebuttal reason is REFUSED (exit 1)
# ---------------------------------------------------------------------------
_run_test 5 \
    "empty commit-msg-rebuttal reason is REFUSED" \
    "Fix thing

No pack ID.

<!-- commit-msg-rebuttal: -->

Co-Authored-By: Test <test@example.com>" \
    1

# ---------------------------------------------------------------------------
# Test 6: oversized rebuttal reason (>200 chars) is REFUSED (exit 1)
# ---------------------------------------------------------------------------
LONG_REASON="$(python3 -c "print('x' * 201)")"
_run_test 6 \
    "oversized commit-msg-rebuttal reason (>200 chars) is REFUSED" \
    "Fix thing

No pack ID.

<!-- commit-msg-rebuttal: ${LONG_REASON} -->

Co-Authored-By: Test <test@example.com>" \
    1

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS_COUNT PASS, $FAIL_COUNT FAIL"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
echo "All $PASS_COUNT tests PASS"
exit 0
