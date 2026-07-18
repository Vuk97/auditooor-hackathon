#!/usr/bin/env bash
# test_audit_deep_live_flag.sh — I12 (#327) regression tests for the
# `--live` / `AUDIT_DEEP_LIVE=1` flag on tools/audit-deep.sh.
#
# Background: audit-deep used to hardcode `--dry-run` into the inner
# symbolic-runner and fuzz-runner invocations. The user-facing report
# said "ran: halmos medusa slither" but only Slither actually ran.
# Halmos/Medusa were dry-run; their reports said `status: skipped`.
#
# Fix: audit-deep accepts `--live` (or `AUDIT_DEEP_LIVE=1`) which drops
# the inner `--dry-run` so the engines actually invoke. The default
# stays opt-in-cheap (planned + slither) so existing CI doesn't get
# surprise multi-hour runs.
#
# Hermetic: scaffold a fake symbolic-runner / fuzz-runner that records
# whether they were invoked with `--dry-run` or not. Audit-deep is
# called twice — once without --live (must pass --dry-run to runners),
# once with --live (must NOT pass --dry-run).

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AUDIT_DEEP="$ROOT/tools/audit-deep.sh"

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

# Scaffold a workspace with the minimum stubs audit-deep needs.
_scaffold_ws() {
    local ws="$1"
    mkdir -p "$ws/.audit_logs" "$ws/src/protocol"
    cat > "$ws/src/protocol/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    # audit-deep guards on intake-baseline; provide a minimal one.
    cat > "$ws/INTAKE_BASELINE.json" <<EOF
{ "schema_version": 1, "assets_in_scope": ["Smart Contract"] }
EOF
}

# Scaffold fake symbolic-runner / fuzz-runner shims that record whether
# they got --dry-run or not. We replace the real scripts on PATH by
# pointing audit-deep at a copy of the auditooor tools/ tree where the
# scripts are replaced. To keep the test hermetic we instead rely on
# audit-deep's HERE-resolved path: we copy audit-deep + the fakes into
# a tempdir so HERE points at the tempdir.
_scaffold_fake_runners() {
    local td="$1"
    mkdir -p "$td/tools" "$td/tools/lib" "$td/bin"
    # Copy the real audit-deep + its lib helpers
    cp "$ROOT/tools/audit-deep.sh" "$td/tools/audit-deep.sh"
    if [ -d "$ROOT/tools/lib" ]; then
        cp -r "$ROOT/tools/lib/." "$td/tools/lib/"
    fi
    # Replace the inner runners with a recorder.
    cat > "$td/tools/symbolic-runner.sh" <<'EOF'
#!/usr/bin/env bash
# Fake symbolic-runner that records whether --dry-run was passed.
record_file="${TEST_RECORD_FILE:-/dev/null}"
saw_dry_run=0
for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        saw_dry_run=1
    fi
done
echo "symbolic-runner dry-run=$saw_dry_run argv=$*" >> "$record_file"
exit "${TEST_FORCE_RUNNER_RC:-0}"
EOF
    cat > "$td/tools/fuzz-runner.sh" <<'EOF'
#!/usr/bin/env bash
record_file="${TEST_RECORD_FILE:-/dev/null}"
saw_dry_run=0
for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        saw_dry_run=1
    fi
done
echo "fuzz-runner dry-run=$saw_dry_run argv=$*" >> "$record_file"
exit "${TEST_FORCE_RUNNER_RC:-0}"
EOF
    chmod +x "$td/tools/symbolic-runner.sh" "$td/tools/fuzz-runner.sh"
    # Slither resilient + cross-lane-correlate: stub out so we don't
    # have to install slither for the test to pass.
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
    chmod +x "$td/tools/slither-resilient.sh" "$td/tools/cross-lane-correlate.py"
    # Make tool-availability detect the optional engines so audit-deep enters
    # the runner branches even on CI machines without halmos/medusa installed.
    cat > "$td/bin/halmos" <<'EOF'
#!/usr/bin/env bash
echo "fake-halmos 0.0.0-test"
exit 0
EOF
    cat > "$td/bin/medusa" <<'EOF'
#!/usr/bin/env bash
echo "fake-medusa 0.0.0-test"
exit 0
EOF
    chmod +x "$td/bin/halmos" "$td/bin/medusa"
}

# --- Test 1: default (no --live) passes --dry-run to runners ------------
test_default_passes_dry_run() {
    local td ws record
    td="$(mktemp -d)"
    ws="$td/ws"
    record="$td/record.log"
    _scaffold_ws "$ws"
    _scaffold_fake_runners "$td"

    TEST_RECORD_FILE="$record" PATH="$td/bin:$PATH" \
        bash "$td/tools/audit-deep.sh" "$ws" >/dev/null 2>&1 || true

    if grep -q "symbolic-runner dry-run=1" "$record" 2>/dev/null; then
        _pass "default audit-deep passes --dry-run to symbolic-runner"
    else
        _fail "default audit-deep did NOT pass --dry-run to symbolic-runner (record: $(cat "$record" 2>/dev/null || echo MISSING))"
    fi
    if grep -q "fuzz-runner dry-run=1" "$record" 2>/dev/null; then
        _pass "default audit-deep passes --dry-run to fuzz-runner"
    else
        _fail "default audit-deep did NOT pass --dry-run to fuzz-runner (record: $(cat "$record" 2>/dev/null || echo MISSING))"
    fi
    if grep -q "| halmos | dry_run |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null &&
       grep -q "| medusa | dry_run |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null; then
        _pass "default audit-deep classifies Halmos/Medusa as dry_run"
    else
        _fail "default audit-deep did not classify Halmos/Medusa as dry_run"
    fi
    if grep -q "ran: .*halmos (planned-only" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null ||
       grep -q "ran: .*medusa (planned-only" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null; then
        _fail "default audit-deep still reports planned-only Halmos/Medusa as ran"
    else
        _pass "default audit-deep does not report planned-only Halmos/Medusa as ran"
    fi
    rm -rf "$td"
}

# --- Test 2: --live drops --dry-run from runner invocations -------------
test_live_flag_drops_dry_run() {
    local td ws record
    td="$(mktemp -d)"
    ws="$td/ws"
    record="$td/record.log"
    _scaffold_ws "$ws"
    _scaffold_fake_runners "$td"

    TEST_RECORD_FILE="$record" PATH="$td/bin:$PATH" \
        bash "$td/tools/audit-deep.sh" --live "$ws" >/dev/null 2>&1 || true

    if grep -q "symbolic-runner dry-run=0" "$record" 2>/dev/null; then
        _pass "--live audit-deep drops --dry-run from symbolic-runner"
    else
        _fail "--live audit-deep still passed --dry-run to symbolic-runner (record: $(cat "$record" 2>/dev/null || echo MISSING))"
    fi
    if grep -q "fuzz-runner dry-run=0" "$record" 2>/dev/null; then
        _pass "--live audit-deep drops --dry-run from fuzz-runner"
    else
        _fail "--live audit-deep still passed --dry-run to fuzz-runner (record: $(cat "$record" 2>/dev/null || echo MISSING))"
    fi
    if grep -q "| halmos | executed |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null &&
       grep -q "| medusa | executed |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null; then
        _pass "--live audit-deep classifies Halmos/Medusa as executed"
    else
        _fail "--live audit-deep did not classify Halmos/Medusa as executed"
    fi
    rm -rf "$td"
}

# --- Test 3: AUDIT_DEEP_LIVE=1 env equivalent to --live -----------------
test_env_var_drops_dry_run() {
    local td ws record td_alias ws_alias record_alias
    td="$(mktemp -d)"
    ws="$td/ws"
    record="$td/record.log"
    _scaffold_ws "$ws"
    _scaffold_fake_runners "$td"

    TEST_RECORD_FILE="$record" AUDIT_DEEP_LIVE=1 PATH="$td/bin:$PATH" \
        bash "$td/tools/audit-deep.sh" "$ws" >/dev/null 2>&1 || true

    if grep -q "symbolic-runner dry-run=0" "$record" 2>/dev/null; then
        _pass "AUDIT_DEEP_LIVE=1 env drops --dry-run from symbolic-runner"
    else
        _fail "AUDIT_DEEP_LIVE=1 env did NOT drop --dry-run from symbolic-runner (record: $(cat "$record" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"

    td_alias="$(mktemp -d)"
    ws_alias="$td_alias/ws"
    record_alias="$td_alias/record.log"
    _scaffold_ws "$ws_alias"
    _scaffold_fake_runners "$td_alias"

    TEST_RECORD_FILE="$record_alias" AUDITOOOR_AUDIT_DEEP_LIVE=1 PATH="$td_alias/bin:$PATH" \
        bash "$td_alias/tools/audit-deep.sh" "$ws_alias" >/dev/null 2>&1 || true

    if grep -q "symbolic-runner dry-run=0" "$record_alias" 2>/dev/null; then
        _pass "AUDITOOOR_AUDIT_DEEP_LIVE=1 env drops --dry-run from symbolic-runner"
    else
        _fail "AUDITOOOR_AUDIT_DEEP_LIVE=1 env did NOT drop --dry-run from symbolic-runner (record: $(cat "$record_alias" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td_alias"
}

# --- Test 4: dry-run-of-audit-deep itself preserves --dry-run path ----
test_dry_run_audit_deep_renders_planned() {
    local td ws record
    td="$(mktemp -d)"
    ws="$td/ws"
    record="$td/record.log"
    _scaffold_ws "$ws"
    _scaffold_fake_runners "$td"

    TEST_RECORD_FILE="$record" PATH="$td/bin:$PATH" \
        bash "$td/tools/audit-deep.sh" --dry-run "$ws" >/dev/null 2>&1 || true

    # When audit-deep itself is dry-run, the inner runners must NOT be
    # invoked at all (only "planned: ..." text is emitted to the report).
    if [ ! -f "$record" ] || ! grep -q "symbolic-runner\|fuzz-runner" "$record" 2>/dev/null; then
        _pass "audit-deep --dry-run does NOT invoke inner runners"
    else
        _fail "audit-deep --dry-run invoked inner runners (record: $(cat "$record"))"
    fi
    if grep -q "| halmos | planned |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null &&
       grep -q "| medusa | planned |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null; then
        _pass "audit-deep --dry-run classifies Halmos/Medusa as planned"
    else
        _fail "audit-deep --dry-run did not classify Halmos/Medusa as planned"
    fi
    rm -rf "$td"
}

test_runner_nonzero_classifies_blocked() {
    local td ws record
    td="$(mktemp -d)"
    ws="$td/ws"
    record="$td/record.log"
    _scaffold_ws "$ws"
    _scaffold_fake_runners "$td"

    TEST_RECORD_FILE="$record" TEST_FORCE_RUNNER_RC=2 PATH="$td/bin:$PATH" \
        bash "$td/tools/audit-deep.sh" --live "$ws" >/dev/null 2>&1 || true

    if grep -q "| halmos | blocked | symbolic-runner rc=2 |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null &&
       grep -q "| medusa | blocked | fuzz-runner rc=2 |" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null; then
        _pass "non-zero Halmos/Medusa runner exits classify as blocked"
    else
        _fail "non-zero Halmos/Medusa runner exits were not classified as blocked"
    fi
    if grep -q "ran: .*halmos (live)" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null ||
       grep -q "ran: .*medusa (live)" "$ws/.audit_logs/audit_deep_report.md" 2>/dev/null; then
        _fail "blocked Halmos/Medusa runner exits still reported as ran"
    else
        _pass "blocked Halmos/Medusa runner exits are not reported as ran"
    fi
    rm -rf "$td"
}

test_project_root_forwarded_to_inner_runners() {
    local td ws record project
    td="$(mktemp -d)"
    ws="$td/ws"
    record="$td/record.log"
    project="$ws/external/stableswap-hooks"
    _scaffold_ws "$ws"
    mkdir -p "$project"
    cat > "$project/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    _scaffold_fake_runners "$td"

    TEST_RECORD_FILE="$record" PATH="$td/bin:$PATH" \
        bash "$td/tools/audit-deep.sh" --live --project-root "$project" "$ws" >/dev/null 2>&1 || true

    if grep -q "symbolic-runner .*--project-root $project" "$record" 2>/dev/null; then
        _pass "--project-root is forwarded to symbolic-runner"
    else
        _fail "--project-root was not forwarded to symbolic-runner (record: $(cat "$record" 2>/dev/null || echo MISSING))"
    fi
    if grep -q "fuzz-runner .*--project-root $project" "$record" 2>/dev/null; then
        _pass "--project-root is forwarded to fuzz-runner"
    else
        _fail "--project-root was not forwarded to fuzz-runner (record: $(cat "$record" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"
}

echo "[test_audit_deep_live_flag.sh] running 6 test cases"
test_default_passes_dry_run
test_live_flag_drops_dry_run
test_env_var_drops_dry_run
test_dry_run_audit_deep_renders_planned
test_runner_nonzero_classifies_blocked
test_project_root_forwarded_to_inner_runners

echo
echo "[test_audit_deep_live_flag.sh] PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
