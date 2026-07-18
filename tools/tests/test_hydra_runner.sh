#!/usr/bin/env bash
# test_hydra_runner.sh — regression tests for tools/hydra-runner.sh.
#
# The runner is the multi-engine aggregator that replaces the prior
# "tools/hydra-runner.sh exists today" lie in TOOL_COST_BENEFIT.md.
# It runs slither + halmos + medusa via the existing wrappers and
# emits an aggregated manifest + report.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNNER="$ROOT/tools/hydra-runner.sh"

FAIL_COUNT=0
PASS_COUNT=0

_pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo "  PASS — $1"; }
_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo "  FAIL — $1" >&2; }

_scaffold_ws() {
    local ws="$1"
    mkdir -p "$ws/src/protocol"
    cat > "$ws/src/protocol/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
}

# --- Test 1: --help exits 0 ---------------------------------------------
test_help() {
    local out
    out="$(bash "$RUNNER" --help 2>&1)"
    if [ $? -eq 0 ] && echo "$out" | grep -q "multi-engine deep-audit aggregator"; then
        _pass "hydra-runner --help works"
    else
        _fail "hydra-runner --help did not work"
    fi
}

# --- Test 2: dry-run emits manifest + report ----------------------------
test_dry_run_emits_artifacts() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws"

    bash "$RUNNER" "$ws" --dry-run >/dev/null 2>&1
    local rc=$?

    if [ "$rc" -eq 0 ]; then
        _pass "hydra-runner --dry-run exits 0"
    else
        _fail "hydra-runner --dry-run exit $rc"
    fi

    local manifest_dir
    manifest_dir="$(find "$ws/hydra_runs" -name hydra_manifest.json -print 2>/dev/null | tail -1)"
    if [ -n "$manifest_dir" ]; then
        _pass "hydra-runner emits hydra_manifest.json"
    else
        _fail "hydra-runner did not emit hydra_manifest.json"
    fi

    local report_dir
    report_dir="$(find "$ws/hydra_runs" -name hydra_report.md -print 2>/dev/null | tail -1)"
    if [ -n "$report_dir" ]; then
        _pass "hydra-runner emits hydra_report.md"
    else
        _fail "hydra-runner did not emit hydra_report.md"
    fi

    rm -rf "$td"
}

# --- Test 3: missing workspace exits 2 ----------------------------------
test_missing_workspace() {
    local rc=0
    bash "$RUNNER" "/tmp/nonexistent-/-no-way-this-exists-99999" --dry-run >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 2 ]; then
        _pass "hydra-runner exits 2 on missing workspace"
    else
        _fail "hydra-runner did not exit 2 on missing workspace (got $rc)"
    fi
}

# --- Test 4: --engines selects subset -----------------------------------
test_engines_subset() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws"

    bash "$RUNNER" "$ws" --dry-run --engines slither >/dev/null 2>&1
    local manifest
    manifest="$(find "$ws/hydra_runs" -name hydra_manifest.json -print 2>/dev/null | tail -1)"
    if [ -f "$manifest" ]; then
        # Manifest should have exactly 1 engine entry.
        local count
        count="$(python3 -c "import json; m=json.load(open('$manifest')); print(len(m['engines']))")"
        if [ "$count" -eq 1 ]; then
            _pass "hydra-runner --engines slither runs 1 engine"
        else
            _fail "hydra-runner --engines slither ran $count engines (expected 1)"
        fi
    else
        _fail "hydra-runner --engines did not emit manifest"
    fi
    rm -rf "$td"
}

# --- Test 5: invalid --engines value exits 2 ----------------------------
test_invalid_engine() {
    local td ws rc
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws"

    rc=0
    bash "$RUNNER" "$ws" --dry-run --engines bogus >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 2 ]; then
        _pass "hydra-runner exits 2 on invalid --engines"
    else
        _fail "hydra-runner did not exit 2 on invalid --engines (got $rc)"
    fi
    rm -rf "$td"
}

# --- Test 6: empty --engines (after parse) exits 2 ---------------------
test_empty_engines() {
    local td ws rc
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws"

    rc=0
    bash "$RUNNER" "$ws" --dry-run --engines "" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 2 ]; then
        _pass "hydra-runner exits 2 on empty --engines"
    else
        _fail "hydra-runner did not exit 2 on empty --engines (got $rc)"
    fi
    rm -rf "$td"
}

# --- Test 7: manifest schema is auditooor.hydra_runner.v1 --------------
test_manifest_schema() {
    local td ws
    td="$(mktemp -d)"
    ws="$td/ws"
    _scaffold_ws "$ws"

    bash "$RUNNER" "$ws" --dry-run >/dev/null 2>&1
    local manifest
    manifest="$(find "$ws/hydra_runs" -name hydra_manifest.json -print 2>/dev/null | tail -1)"
    if grep -q '"schema_version": "auditooor.hydra_runner.v1"' "$manifest" 2>/dev/null; then
        _pass "hydra_manifest.json carries schema_version=auditooor.hydra_runner.v1"
    else
        _fail "hydra_manifest.json schema_version mismatch"
    fi
    rm -rf "$td"
}

echo "[test_hydra_runner.sh] running 7 tests"
test_help
test_dry_run_emits_artifacts
test_missing_workspace
test_engines_subset
test_invalid_engine
test_empty_engines
test_manifest_schema

echo
echo "[test_hydra_runner.sh] PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
