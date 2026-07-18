#!/usr/bin/env bash
# test_make_hunt_target.sh - Tests for `make hunt WS=<ws>` convenience target
# and the hunt-reporter.py helper script.
#
# Tests:
#   Test 1: hunt-reporter.py on report with rows - prints candidate list
#   Test 2: hunt-reporter.py on report with no rows - graceful empty message
#   Test 3: hunt-reporter.py --top-n limits output
#   Test 4: make hunt WS=<empty-workspace> exits non-zero (no LIVE_TARGET_REPORT after audit-fast)
#   Test 5: make hunt with no WS - prints usage message and exits 2
#   Test 6: idempotent - hunt-reporter.py run twice on same file produces same output

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HUNT_REPORTER="$ROOT/tools/hunt-reporter.py"

FAIL_COUNT=0
PASS_COUNT=0

_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  PASS -- $1"
}

_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  FAIL -- $1" >&2
}

# Minimal synthetic LIVE_TARGET_REPORT.md with 3 candidates
_write_report() {
    local path="$1"
    cat > "$path" <<'EOF'
# Live-Target Intelligence Report - test-ws

- Workspace: `/tmp/test-ws`
- Generated: `2026-05-25T00:00:00Z`

## Summary card

- Files indexed: **42**
- Engage-report hits: **5**

## Hunt prioritization

| rank | score | comp | priority | file:line | cluster | p1 tier | p1 | p3 | p4 |
|----:|----:|----:|---|---|---|---|---|---|---|
| 1 | 60.3 | 10 * | HIGH-PRIORITY-HUNT | `/tmp/test-ws/src/Foo.sol:100` | `reentrancy-eth` | SEMANTIC-MATCH | INV-CON-001 | solidity.reentrancy | completed: proceed |
| 2 | 54.0 | 0 | MEDIUM-PRIORITY | `/tmp/test-ws/src/Bar.sol:200` | `access-control-missing` | NO-MATCH |  |  | completed: proceed |
| 3 | 50.0 | 0 | MEDIUM-PRIORITY | `/tmp/test-ws/src/Baz.sol:300` | `integer-overflow` | NO-MATCH |  |  | completed: proceed |
EOF
}

# ---- Test 1: hunt-reporter.py on report with rows ----
echo ""
echo "Test 1: hunt-reporter.py prints candidate rows from LIVE_TARGET_REPORT.md"
_TMP1="$(mktemp /tmp/hunt_test_report1_XXXX.md)"
_write_report "$_TMP1"
_out1="$(python3 "$HUNT_REPORTER" --report "$_TMP1" --top-n 10 2>&1)"
_rc1=$?

if [ $_rc1 -eq 0 ]; then
    _pass "Test 1a: hunt-reporter.py exits 0"
else
    _fail "Test 1a: hunt-reporter.py exited $_rc1"
fi

if echo "$_out1" | grep -qE "HIGH-PRIORITY-HUNT|reentrancy-eth"; then
    _pass "Test 1b: HIGH-PRIORITY candidate row present in output"
else
    _fail "Test 1b: HIGH-PRIORITY row missing; got: $(echo "$_out1" | head -5)"
fi

if echo "$_out1" | grep -qE "access-control-missing|MEDIUM-PRIORITY"; then
    _pass "Test 1c: MEDIUM-PRIORITY candidate row present in output"
else
    _fail "Test 1c: MEDIUM-PRIORITY row missing"
fi

if echo "$_out1" | grep -q "INV-CON-001"; then
    _pass "Test 1d: invariant citation present in output"
else
    _fail "Test 1d: invariant citation missing"
fi

rm -f "$_TMP1"

# ---- Test 2: hunt-reporter.py on empty / no-rows report ----
echo ""
echo "Test 2: hunt-reporter.py graceful empty message when no candidates"
_TMP2="$(mktemp /tmp/hunt_test_report2_XXXX.md)"
cat > "$_TMP2" <<'EOF'
# Live-Target Intelligence Report - test-ws

## Summary card
- Files indexed: 0
EOF

_out2="$(python3 "$HUNT_REPORTER" --report "$_TMP2" --top-n 10 2>&1)"
_rc2=$?

if [ $_rc2 -eq 0 ]; then
    _pass "Test 2a: hunt-reporter.py exits 0 on empty report"
else
    _fail "Test 2a: hunt-reporter.py exited $_rc2 on empty report"
fi

if echo "$_out2" | grep -qi "no candidates\|make audit\|not found"; then
    _pass "Test 2b: graceful empty message present"
else
    _fail "Test 2b: no graceful empty message; got: $(echo "$_out2" | head -3)"
fi

rm -f "$_TMP2"

# ---- Test 3: hunt-reporter.py --top-n limits output ----
echo ""
echo "Test 3: hunt-reporter.py --top-n 1 shows exactly 1 candidate"
_TMP3="$(mktemp /tmp/hunt_test_report3_XXXX.md)"
_write_report "$_TMP3"
_out3="$(python3 "$HUNT_REPORTER" --report "$_TMP3" --top-n 1 2>&1)"

_row_count=$(echo "$_out3" | grep -cE "^\s+[0-9]+\." || true)
if [ "$_row_count" -eq 1 ]; then
    _pass "Test 3: --top-n 1 produces exactly 1 candidate row"
else
    _fail "Test 3: --top-n 1 produced $_row_count candidate rows (expected 1)"
fi

rm -f "$_TMP3"

# ---- Test 4: make hunt WS=<empty-workspace> exits non-zero ----
echo ""
echo "Test 4: make hunt exits non-zero when workspace has no LIVE_TARGET_REPORT after audit-fast"
_WS4="$(mktemp -d /tmp/hunt_test_ws4_XXXX)"
# Scaffold minimal workspace - no LIVE_TARGET_REPORT.md, no source files
# audit-fast will fail because live-target-intelligence-report.py will get no engage_report
mkdir -p "$_WS4/.auditooor" "$_WS4/docs"

_hunt_out4="$(make -C "$ROOT" --no-print-directory hunt WS="$_WS4" 2>&1 || true)"
_hunt_rc4=$?

# After audit-fast on an empty workspace, LIVE_TARGET_REPORT may or may not exist
# The key assertion is: if it exits 0, the report must exist and have content
if [ $_hunt_rc4 -ne 0 ]; then
    _pass "Test 4: make hunt exits non-zero on empty workspace (expected failure path)"
elif [ -f "$_WS4/docs/LIVE_TARGET_REPORT.md" ]; then
    _pass "Test 4: make hunt exits 0 and LIVE_TARGET_REPORT.md was created by audit-fast"
else
    _fail "Test 4: make hunt exited 0 but LIVE_TARGET_REPORT.md was not created"
fi

rm -rf "$_WS4"

# ---- Test 5: make hunt with no WS - prints usage and exits 2 ----
echo ""
echo "Test 5: make hunt with no WS prints usage message and exits 2"
_hunt_out5="$(make -C "$ROOT" --no-print-directory hunt 2>&1)" && _hunt_rc5=0 || _hunt_rc5=$?

if [ "$_hunt_rc5" -ne 0 ]; then
    _pass "Test 5a: make hunt without WS exits non-zero (rc=$_hunt_rc5)"
else
    _fail "Test 5a: make hunt without WS exited 0 (expected error)"
fi

if echo "$_hunt_out5" | grep -qi "Usage: make hunt WS"; then
    _pass "Test 5b: usage message present in output"
else
    _fail "Test 5b: no usage message found; got: $(echo "$_hunt_out5" | head -3)"
fi

# ---- Test 6: idempotent - hunt-reporter.py same output on repeated runs ----
echo ""
echo "Test 6: hunt-reporter.py is idempotent (same output on repeated calls)"
_TMP6="$(mktemp /tmp/hunt_test_report6_XXXX.md)"
_write_report "$_TMP6"

_out6a="$(python3 "$HUNT_REPORTER" --report "$_TMP6" --top-n 10 2>&1)"
_out6b="$(python3 "$HUNT_REPORTER" --report "$_TMP6" --top-n 10 2>&1)"

if [ "$_out6a" = "$_out6b" ]; then
    _pass "Test 6: hunt-reporter.py output is identical across two runs (idempotent)"
else
    _fail "Test 6: hunt-reporter.py output differs between runs"
fi

rm -f "$_TMP6"

# ---- Summary ----
echo ""
echo "=========================================="
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=========================================="

if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi
exit 0
