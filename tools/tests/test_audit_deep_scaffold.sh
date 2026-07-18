#!/usr/bin/env bash
# test_audit_deep_scaffold.sh — I17 (#334) regression tests for the
# `--scaffold` / `AUDIT_DEEP_SCAFFOLD=1` flag on tools/audit-deep.sh.
#
# Hermetic: sandbox HOME, scaffold fake workspaces, mock inner runners,
# assert scaffold file presence/absence and idempotency.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AUDIT_DEEP="$ROOT/tools/audit-deep.sh"
GEN_INVARIANTS="$ROOT/tools/gen-invariants.sh"

FAIL_COUNT=0
PASS_COUNT=0

_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  PASS — $1"
}

_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  FAIL — $1" >&2
}

# Scaffold a fake workspace with optional mining_priorities.json and optional src/contract.
_scaffold_ws() {
    local ws="$1"
    local has_mp="${2:-0}"
    local has_contract="${3:-0}"
    mkdir -p "$ws/.audit_logs" "$ws/src/protocol"
    cat > "$ws/src/protocol/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    if [ "$has_mp" = "1" ]; then
        mkdir -p "$ws/swarm"
        cat > "$ws/swarm/mining_priorities.json" <<EOF
[
  { "id": "A-AUTH", "contract": "TestToken", "title": "Unauthenticated mint: TestToken.mint" }
]
EOF
    fi
    if [ "$has_contract" = "1" ]; then
        cat > "$ws/src/protocol/TestToken.sol" <<EOF
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TestToken {
    function transfer(address to, uint256 amount) external {}
}
EOF
    fi
    cat > "$ws/INTAKE_BASELINE.json" <<EOF
{ "schema_version": 1, "assets_in_scope": ["Smart Contract"] }
EOF
}

# Scaffold fake inner runners so audit-deep doesn't need real halmos/medusa.
_scaffold_fake_runners() {
    local td="$1"
    mkdir -p "$td/tools" "$td/tools/lib"
    cp "$ROOT/tools/audit-deep.sh" "$td/tools/audit-deep.sh"
    if [ -d "$ROOT/tools/lib" ]; then
        cp -r "$ROOT/tools/lib/." "$td/tools/lib/"
    fi
    # Use real gen-invariants.sh (it falls back to generic when templates are missing)
    cp "$GEN_INVARIANTS" "$td/tools/gen-invariants.sh"
    cat > "$td/tools/symbolic-runner.sh" <<'EOF'
#!/usr/bin/env bash
echo "fake-symbolic-runner $*" >> "${TEST_RECORD_FILE:-/dev/null}"
exit 0
EOF
    cat > "$td/tools/fuzz-runner.sh" <<'EOF'
#!/usr/bin/env bash
echo "fake-fuzz-runner $*" >> "${TEST_RECORD_FILE:-/dev/null}"
exit 0
EOF
    cat > "$td/tools/slither-resilient.sh" <<'EOF'
#!/usr/bin/env bash
echo "fake-slither-resilient $*" >> "${TEST_RECORD_FILE:-/dev/null}"
exit 0
EOF
    cat > "$td/tools/cross-lane-correlate.py" <<'EOF'
#!/usr/bin/env python3
import sys
sys.exit(0)
EOF
    chmod +x "$td/tools/symbolic-runner.sh" "$td/tools/fuzz-runner.sh" \
        "$td/tools/slither-resilient.sh" "$td/tools/cross-lane-correlate.py"
}

# --- Test 1: default (no --scaffold) does NOT emit scaffold -----------------
test_default_no_scaffold() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws" 1 1
    _scaffold_fake_runners "$td"

    bash "$td/tools/audit-deep.sh" --live "$ws" >/dev/null 2>&1 || true

    if [ ! -f "$ws/test/Invariant_TestToken.t.sol" ]; then
        _pass "default (no --scaffold) does not emit scaffold file"
    else
        _fail "default (no --scaffold) unexpectedly emitted scaffold file"
    fi
    rm -rf "$td"
}

# --- Test 2: --scaffold + --live + mining_priorities + no existing harness ---
test_scaffold_emits_file() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws" 1 1
    _scaffold_fake_runners "$td"

    bash "$td/tools/audit-deep.sh" --live --scaffold "$ws" >/dev/null 2>&1 || true

    if [ -f "$ws/test/Invariant_TestToken.t.sol" ]; then
        _pass "--scaffold + --live emits Invariant_TestToken.t.sol in resolved test dir"
    else
        _fail "--scaffold + --live did NOT emit scaffold file in resolved test dir"
    fi
    rm -rf "$td"
}

# --- Test 3: --scaffold + existing harness = no overwrite -------------------
test_scaffold_idempotent() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws" 1 1
    _scaffold_fake_runners "$td"

    mkdir -p "$ws/test"
    echo "// existing" > "$ws/test/Invariant_TestToken.t.sol"

    bash "$td/tools/audit-deep.sh" --live --scaffold "$ws" >/dev/null 2>&1 || true

    if [ -f "$ws/test/Invariant_TestToken.t.sol" ]; then
        local content
        content="$(cat "$ws/test/Invariant_TestToken.t.sol")"
        if [ "$content" = "// existing" ]; then
            _pass "--scaffold is idempotent (does not overwrite existing)"
        else
            _fail "--scaffold overwrote existing harness"
        fi
    else
        _fail "--scaffold deleted existing harness"
    fi
    rm -rf "$td"
}

# --- Test 4: --scaffold + no mining_priorities = graceful skip -------------
test_scaffold_no_mining_priorities() {
    local td ws report
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws" 0 0
    _scaffold_fake_runners "$td"

    bash "$td/tools/audit-deep.sh" --live --scaffold "$ws" >/dev/null 2>&1 || true

    if [ ! -f "$ws/test/Invariant_TestToken.t.sol" ]; then
        _pass "--scaffold with no mining_priorities.json gracefully skips"
    else
        _fail "--scaffold with no mining_priorities.json unexpectedly emitted file"
    fi

    report="$ws/.audit_logs/audit_deep_report.md"
    if [ -f "$report" ] && grep -q "scaffold: SKIPPED (no mining_priorities.json" "$report" 2>/dev/null; then
        _pass "report warns when mining_priorities.json is missing"
    else
        _fail "report missing skip warning for missing mining_priorities.json"
    fi
    rm -rf "$td"
}

# --- Test 5: I20 — custom test dir from foundry.toml ------------------------
test_scaffold_respects_custom_test_dir() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws" 1 1
    _scaffold_fake_runners "$td"

    # Override the foundry.toml with a custom test dir
    cat > "$ws/src/protocol/foundry.toml" <<EOF
[profile.default]
src = "src"
test = "custom-tests"
out = "out"
EOF

    bash "$td/tools/audit-deep.sh" --live --scaffold "$ws" >/dev/null 2>&1 || true

    if [ -f "$ws/custom-tests/Invariant_TestToken.t.sol" ]; then
        _pass "I20: scaffold lands in custom test dir from foundry.toml"
    else
        _fail "I20: scaffold did NOT land in custom test dir"
    fi
    rm -rf "$td"
}

# --- Test 6: I21 — Property_<X>.t.sol is also created -----------------------
test_scaffold_emits_property_for_medusa() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws" 1 1
    _scaffold_fake_runners "$td"

    bash "$td/tools/audit-deep.sh" --live --scaffold "$ws" >/dev/null 2>&1 || true

    if [ -f "$ws/test/Property_TestToken.t.sol" ]; then
        _pass "I21: --scaffold emits Property_TestToken.t.sol for medusa"
    else
        _fail "I21: --scaffold did NOT emit Property_TestToken.t.sol"
    fi
    if grep -q "function property_placeholder() external returns (bool)" "$ws/test/Property_TestToken.t.sol" \
        && grep -q "_medusaRuns++" "$ws/test/Property_TestToken.t.sol"; then
        _pass "I22: medusa placeholder is non-view and call-generator friendly"
    else
        _fail "I22: medusa placeholder still uses undiscoverable/view shape"
    fi
    rm -rf "$td"
}

# --- Test 7: I22 (#344) — end-to-end medusa discovery on the gen-invariants ---
# scaffold output. Skipped automatically if medusa, forge, or crytic-compile
# are not installed on the runner.
#
# Bisection result captured by this test:
#   * `public view returns (bool)` is technically discoverable but yields a
#     "cannot generate fuzzed call" loop error (no methods to call).
#   * The scaffold emitted by gen-invariants.sh — `external returns (bool)`
#     with a state-mutating body and `is Test` parent — runs cleanly to
#     `[PASSED] Property Test: Property_TestToken.property_placeholder()`.
#   * The crytic-compile `--skip ./test/**` default is bypassed by the
#     fuzz-runner's `--compilation-target <PROP_FILE>` patch (PR #343, ext.).
test_medusa_discovers_property_scaffold() {
    if ! command -v medusa >/dev/null 2>&1; then
        echo "  SKIP — medusa not installed; cannot verify discovery end-to-end"
        return 0
    fi
    if ! command -v forge >/dev/null 2>&1; then
        echo "  SKIP — forge not installed; cannot bootstrap Foundry workspace"
        return 0
    fi
    if ! command -v crytic-compile >/dev/null 2>&1; then
        echo "  SKIP — crytic-compile not installed; medusa cannot compile"
        return 0
    fi

    local td ws log
    td="$(mktemp -d)"
    ws="$td/ws"
    log="$td/medusa.log"
    mkdir -p "$ws"

    # Build a minimal Foundry workspace with a TestToken and the gen-invariants
    # property harness in workspace/test/.
    if ! (cd "$ws" && forge init --no-git . >/dev/null 2>&1); then
        echo "  SKIP — forge init failed; agent runner network/cache may be sandboxed"
        rm -rf "$td"
        return 0
    fi
    rm -f "$ws/src/Counter.sol" "$ws/test/Counter.t.sol" "$ws/script/Counter.s.sol"
    cat > "$ws/src/TestToken.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestToken {
    function transfer(address to, uint256 amount) external {}
}
EOF

    bash "$GEN_INVARIANTS" "$ws/src/TestToken.sol" "$ws" --engine medusa >/dev/null 2>&1 || true
    if [ ! -f "$ws/test/Property_TestToken.t.sol" ]; then
        _fail "I22 e2e: gen-invariants did not emit Property_TestToken.t.sol"
        rm -rf "$td"
        return 0
    fi

    # Run medusa with the exact flags fuzz-runner.sh uses for property harnesses
    # (target-contracts + compilation-target). Cap at 30s — the property always
    # passes, so medusa exits as soon as the test-limit is reached.
    (
        cd "$ws" && \
        timeout 30 medusa fuzz \
            --target-contracts Property_TestToken \
            --test-limit 50 \
            --compilation-target test/Property_TestToken.t.sol \
            >"$log" 2>&1
    ) || true

    if grep -q "no assertion, property, optimization, or custom tests were found to fuzz" "$log"; then
        _fail "I22 e2e: medusa still reports 'no property tests found' on gen-invariants scaffold"
        echo "  --- medusa.log tail ---"
        tail -20 "$log" | sed 's/^/  /' >&2
    elif grep -Eq '\[PASSED\][^[:alnum:]]+Property Test: Property_TestToken\.property_placeholder' "$log"; then
        _pass "I22 e2e: medusa discovers + runs property_placeholder against the scaffold"
    elif grep -Eq 'Property Test: Property_TestToken\.property_placeholder' "$log"; then
        # Discovery happened (Property Test name printed) even if test-limit
        # cut us off before the PASSED line. That's still success: the bug
        # in #344 was discovery failure, not result reporting.
        _pass "I22 e2e: medusa discovers property_placeholder (test-limit cut before PASSED line)"
    else
        _fail "I22 e2e: medusa output did not show property_placeholder discovery"
        echo "  --- medusa.log tail ---"
        tail -20 "$log" | sed 's/^/  /' >&2
    fi

    rm -rf "$td"
}

echo "[test_audit_deep_scaffold.sh] running 7 test cases"
test_default_no_scaffold
test_scaffold_emits_file
test_scaffold_idempotent
test_scaffold_no_mining_priorities
test_scaffold_respects_custom_test_dir
test_scaffold_emits_property_for_medusa
test_medusa_discovers_property_scaffold

echo
echo "[test_audit_deep_scaffold.sh] PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
