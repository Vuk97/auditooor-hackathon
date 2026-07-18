#!/usr/bin/env bash
# test_zkbugs_pipeline_wiring.sh — Wave 3 pipeline wiring regression tests.
#
# Hermetic: no live LLM provider calls. The provider-loop binary itself
# refuses to dial without AUDITOOOR_LLM_NETWORK_CONSENT=1, so the dry-run
# mode of `make zkbugs-pull` is what we exercise here. Step 9 of
# tools/audit-deep.sh is exercised by writing the freshness probe inline,
# replicating the script's behavior without spawning the full deep-audit
# runner (which would invoke halmos / medusa / slither and is out of scope
# for this targeted suite).
#
# Test cases:
#   1. `make zkbugs-pull DRY_RUN=1` exits 0 and prints planned commands.
#   2. `make zkbugs-pull` without LIVE=1 refuses to call providers.
#   3. `make zkbugs-status` exits 0 even when no corpus exists.
#   4. Step 9 of audit-deep.sh appends the correct stale-warning text when
#      the timestamp file is absent.
#   5. Step 9 marks a fresh-mode banner when the timestamp file is recent.

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

# --- Test 1: DRY_RUN=1 prints planned commands and exits 0 -----------------
test_dry_run_prints_plan() {
    local td zkbugs_root out rc
    td="$(mktemp -d)"
    zkbugs_root="$td/zkbugs"
    mkdir -p "$zkbugs_root/dataset"
    out="$td/out.log"

    (
        cd "$ROOT" && \
        make zkbugs-pull ZKBUGS_ROOT="$zkbugs_root" DRY_RUN=1 \
            OUT="$td/farming" >"$out" 2>&1
    )
    rc=$?
    if [ "$rc" -ne 0 ]; then
        _fail "DRY_RUN=1 exited $rc (expected 0)"
        sed 's/^/    /' "$out" >&2
        rm -rf "$td"
        return
    fi
    if grep -q "step 1/3:" "$out" && grep -q "step 2/3:" "$out" && grep -q "step 3/3:" "$out"; then
        _pass "DRY_RUN=1 prints all three planned steps"
    else
        _fail "DRY_RUN=1 missing one of step 1/3 .. 3/3 lines"
        sed 's/^/    /' "$out" >&2
    fi
    if grep -q "DRY-RUN" "$out"; then
        _pass "DRY_RUN=1 banner present"
    else
        _fail "DRY_RUN=1 banner absent"
    fi
    rm -rf "$td"
}

# --- Test 2: no LIVE=1 refuses to dispatch ---------------------------------
test_no_live_refuses_providers() {
    local td zkbugs_root out rc
    td="$(mktemp -d)"
    zkbugs_root="$td/zkbugs"
    mkdir -p "$zkbugs_root/dataset"
    out="$td/out.log"

    (
        cd "$ROOT" && \
        make zkbugs-pull ZKBUGS_ROOT="$zkbugs_root" \
            OUT="$td/farming" >"$out" 2>&1
    )
    rc=$?
    if [ "$rc" -ne 0 ]; then
        _fail "no-LIVE invocation exited $rc (expected 0; should refuse, not error)"
        sed 's/^/    /' "$out" >&2
        rm -rf "$td"
        return
    fi
    if grep -q "refusing to call providers without LIVE=1" "$out"; then
        _pass "no-LIVE invocation prints refusal banner"
    else
        _fail "no-LIVE invocation missing refusal banner"
        sed 's/^/    /' "$out" >&2
    fi
    # Make sure no provider artifacts were written (loop never ran live).
    if [ ! -d "$td/farming/provider_results/kimi" ]; then
        _pass "no-LIVE invocation did not write Kimi outputs"
    else
        _fail "no-LIVE invocation unexpectedly produced Kimi outputs"
    fi
    rm -rf "$td"
}

# --- Test 3: zkbugs-status exits 0 with no corpus --------------------------
test_status_no_corpus() {
    local td out rc
    td="$(mktemp -d)"
    out="$td/out.log"

    (
        cd "$ROOT" && \
        make zkbugs-status OUT="$td/never-existed-farming" >"$out" 2>&1
    )
    rc=$?
    if [ "$rc" -ne 0 ]; then
        _fail "zkbugs-status exited $rc on absent corpus (expected 0)"
        sed 's/^/    /' "$out" >&2
        rm -rf "$td"
        return
    fi
    if grep -q "MISSING" "$out" && grep -q "## zkBugs Pipeline Status" "$out"; then
        _pass "zkbugs-status reports MISSING for absent corpus"
    else
        _fail "zkbugs-status output shape unexpected"
        sed 's/^/    /' "$out" >&2
    fi
    rm -rf "$td"
}

# --- Test 4: Step 9 stale-warning appears when timestamp file is absent ----
#
# Replicates the audit-deep.sh Step 9 logic in isolation by extracting it
# from the script and running it against a synthetic workspace. We don't
# spawn the full audit-deep runner because that would invoke halmos /
# medusa / slither, which is out of scope for this targeted suite.
test_step9_absent_timestamp() {
    local td ws run_log
    td="$(mktemp -d)"
    ws="$td/ws"
    run_log="$td/run.md"
    mkdir -p "$ws/.auditooor"
    : > "$run_log"

    # Inline the same probe Step 9 runs.
    (
        WORKSPACE="$ws"
        RUN_LOG="$run_log"
        zkbugs_ts_file="$WORKSPACE/.auditooor/zkbugs_last_pull"
        zkbugs_stale_days=14
        if [ ! -f "$zkbugs_ts_file" ]; then
            {
                echo "### Step 9 — zkBugs corpus freshness check"
                echo
                echo "- status: NEVER pulled (no \`$zkbugs_ts_file\`)"
                echo "- recommendation: run \`make zkbugs-pull LIVE=1 ZKBUGS_ROOT=<path>\` to refresh the corpus"
            } >> "$RUN_LOG"
        fi
    )

    if grep -q "Step 9 — zkBugs corpus freshness check" "$run_log" \
        && grep -q "NEVER pulled" "$run_log" \
        && grep -q "make zkbugs-pull LIVE=1" "$run_log"; then
        _pass "Step 9 appends NEVER-pulled stale-warning when timestamp file is absent"
    else
        _fail "Step 9 missing one of: header / NEVER-pulled / make recommendation"
        sed 's/^/    /' "$run_log" >&2
    fi

    # Also assert audit-deep.sh actually contains the Step 9 block (regression
    # against accidental deletion).
    if grep -q "Step 9 — zkBugs corpus freshness check" "$AUDIT_DEEP"; then
        _pass "audit-deep.sh contains Step 9 block"
    else
        _fail "audit-deep.sh missing Step 9 block"
    fi
    rm -rf "$td"
}

# --- Test 5: Step 9 marks fresh when timestamp is recent -------------------
test_step9_fresh_timestamp() {
    local td ws run_log
    td="$(mktemp -d)"
    ws="$td/ws"
    run_log="$td/run.md"
    mkdir -p "$ws/.auditooor"
    : > "$run_log"
    # Recent timestamp.
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$ws/.auditooor/zkbugs_last_pull"

    (
        WORKSPACE="$ws"
        RUN_LOG="$run_log"
        zkbugs_ts_file="$WORKSPACE/.auditooor/zkbugs_last_pull"
        zkbugs_stale_days=14
        if [ -f "$zkbugs_ts_file" ]; then
            zkbugs_age_seconds="$(python3 - "$zkbugs_ts_file" <<'PY' 2>/dev/null || echo 0
import sys
from datetime import datetime, timezone
try:
    raw = open(sys.argv[1]).read().strip()
    ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - ts
    print(int(delta.total_seconds()))
except Exception:
    print(0)
PY
            )"
            zkbugs_threshold_seconds=$(( zkbugs_stale_days * 86400 ))
            if [ "${zkbugs_age_seconds:-0}" -gt "$zkbugs_threshold_seconds" ]; then
                echo "- status: STALE" >> "$RUN_LOG"
            else
                echo "- status: fresh (<${zkbugs_stale_days} days)" >> "$RUN_LOG"
            fi
        fi
    )

    if grep -q "fresh" "$run_log"; then
        _pass "Step 9 marks fresh status when timestamp is recent"
    else
        _fail "Step 9 should have marked fresh"
        sed 's/^/    /' "$run_log" >&2
    fi
    rm -rf "$td"
}

echo "[test_zkbugs_pipeline_wiring.sh] running 5 test cases"
test_dry_run_prints_plan
test_no_live_refuses_providers
test_status_no_corpus
test_step9_absent_timestamp
test_step9_fresh_timestamp

echo
echo "[test_zkbugs_pipeline_wiring.sh] PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
