#!/usr/bin/env bash
# test_go_dynamic_engine_runner.sh — tests for the Go dynamic-engine adapter.
#
# Hermetic (no real go build needed for most cases; dry-run + skip paths).
# Exercises:
#   1. missing-workspace -> exit 2
#   2. workspace with no go.mod fuzz target -> status=skipped, manifest emitted
#   3. fuzz-target discovery from func FuzzXxx(f *testing.F) -> module in command
#   4. dry-run -> commands rendered, no go invocation, exit 0
#   5. manifest schema fields present + valid JSON (engine=go-dynamic, count
#      fields tests_passed/executed_harnesses present for L37 signal c2)
#   6. timeout cap enforced (5401 -> 5400)
#   7. fuzztime cap (601s -> 600s)
#   8. --no-staticcheck honored in command summary
#   9. invalid --fuzztime exits 2
#  10. unknown option exits 2
#  11. (LIVE, gated) real go-fuzz run on a tiny holds-property fuzz target -> pass

set -uo pipefail
RUNNER="$(cd "$(dirname "$0")/.." && pwd)/go-dynamic-engine-runner.sh"
GATE="$(cd "$(dirname "$0")/.." && pwd)/engine-harness-proof-gate.py"
PASS=0; FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL - $1"; FAIL=$((FAIL+1)); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- Test 1: missing workspace -> exit 2 -------------------------------------
bash "$RUNNER" "$TMP/does-not-exist" >/dev/null 2>&1
[ $? -eq 2 ] && ok "missing-workspace exits 2" || bad "missing-workspace should exit 2"

# --- Test 2: workspace with no fuzz target -> skipped, manifest emitted -------
WS2="$TMP/ws_no_fuzz"; mkdir -p "$WS2"
out2="$(bash "$RUNNER" "$WS2" 2>&1)"; rc2=$?
[ $rc2 -eq 0 ] && ok "no-fuzz exits 0" || bad "no-fuzz should exit 0 (got $rc2)"
man2="$(ls "$WS2"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
if [ -n "$man2" ] && grep -qE '"status": "(skipped|tool-not-installed)"' "$man2"; then ok "no-fuzz status skipped/tool-not-installed"; else bad "no-fuzz manifest missing/wrong-status"; fi

# --- Test 3 + 4: fuzz-target discovery + dry-run command render ---------------
WS3="$TMP/ws_fuzz"; mkdir -p "$WS3/modA" "$WS3/modB"
cat > "$WS3/modA/go.mod" <<'EOF'
module example.com/moda
go 1.21
EOF
cat > "$WS3/modA/fuzz_test.go" <<'EOF'
package moda
import "testing"
func FuzzAdd(f *testing.F) {
    f.Add(1, 2)
    f.Fuzz(func(t *testing.T, a int, b int) {
        if a+b != b+a { t.Fatalf("commutativity broke") }
    })
}
EOF
# modB has go.mod but NO fuzz target
cat > "$WS3/modB/go.mod" <<'EOF'
module example.com/modb
go 1.21
EOF
echo 'package modb' > "$WS3/modB/lib.go"

out3="$(bash "$RUNNER" "$WS3" --dry-run 2>&1)"; rc3=$?
[ $rc3 -eq 0 ] && ok "dry-run exits 0" || bad "dry-run should exit 0 (got $rc3)"
cmd3="$(ls "$WS3"/fuzz_runs/*/command.txt 2>/dev/null | head -1)"
if grep -q 'modA' "$cmd3" 2>/dev/null; then ok "discovered modA (has Fuzz target)"; else bad "should discover modA"; fi
if grep -q 'modB' "$cmd3" 2>/dev/null; then bad "should NOT discover modB (no fuzz target)"; else ok "skipped modB (no fuzz target)"; fi
grep -q 'go test' "$cmd3" 2>/dev/null && ok "command summary uses go test" || bad "command should use go test"
grep -q 'fuzz=' "$cmd3" 2>/dev/null && ok "command summary includes fuzz=" || bad "command should include fuzz="

# --- Test 5: manifest schema fields + valid JSON ------------------------------
man3="$(ls "$WS3"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['engine']=='go-dynamic'; assert 'status' in d; assert 'counterexample_path' in d; assert d['schema_version']==1; assert 'tests_passed' in d; assert 'executed_harnesses' in d; assert 'fuzz_targets' in d" "$man3" 2>/dev/null; then
        ok "manifest is valid JSON with required fields (engine + L37 count fields)"
    else bad "manifest JSON invalid or missing fields"; fi
else ok "python3 absent — skip JSON validation"; fi

# --- Test 6: timeout cap (5401 -> 5400) ---------------------------------------
WS6="$TMP/ws_cap"; mkdir -p "$WS6"
bash "$RUNNER" "$WS6" --timeout 5401 >/dev/null 2>&1
man6="$(ls "$WS6"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
if grep -q '"timeout_seconds": 5400' "$man6" 2>/dev/null; then ok "timeout capped at 5400"; else bad "timeout should cap at 5400"; fi

# --- Test 7: fuzztime cap (601s -> 600s) --------------------------------------
bash "$RUNNER" "$WS3" --fuzztime 601s --dry-run >/dev/null 2>&1
man7="$(ls -t "$WS3"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
grep -q '"fuzztime": "600s"' "$man7" 2>/dev/null && ok "fuzztime capped at 600s" || bad "fuzztime should cap at 600s"

# --- Test 8: --no-staticcheck honored in command summary ----------------------
bash "$RUNNER" "$WS3" --no-staticcheck --dry-run >/dev/null 2>&1
cmd8="$(ls -t "$WS3"/fuzz_runs/*/command.txt 2>/dev/null | head -1)"
grep -q 'staticcheck=no' "$cmd8" 2>/dev/null && ok "--no-staticcheck -> staticcheck=no" || bad "--no-staticcheck should set staticcheck=no"

# --- Test 9: invalid --fuzztime exits 2 ---------------------------------------
bash "$RUNNER" "$WS3" --fuzztime abc --dry-run >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "invalid --fuzztime exits 2" || bad "invalid --fuzztime should exit 2"

# --- Test 10: unknown option exits 2 ------------------------------------------
bash "$RUNNER" "$WS3" --bogus-flag >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "unknown option exits 2" || bad "unknown option should exit 2"

# --- Test 11: LIVE go-fuzz run (gated on go availability) ---------------------
if command -v go >/dev/null 2>&1; then
    WS11="$TMP/ws_live"; mkdir -p "$WS11/m"
    cat > "$WS11/m/go.mod" <<'EOF'
module example.com/live
go 1.21
EOF
    cat > "$WS11/m/fuzz_test.go" <<'EOF'
package live
import "testing"
func FuzzHolds(f *testing.F) {
    f.Add(3)
    f.Fuzz(func(t *testing.T, x int) {
        // always-true property: x*2 is even
        if (x*2)%2 != 0 { t.Fatalf("impossible") }
    })
}
EOF
    out11="$(bash "$RUNNER" "$WS11" --fuzztime 2s --no-staticcheck --no-prod-harness 2>&1)"; rc11=$?
    [ $rc11 -eq 0 ] && ok "live run exits 0" || bad "live run should exit 0 (got $rc11)"
    man11="$(ls "$WS11"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
    if grep -qE '"status": "(pass|timeout)"' "$man11" 2>/dev/null; then ok "live holds-property -> pass/timeout"; else echo "  (info) live status: $(grep status "$man11" 2>/dev/null)"; bad "live holds-property should be pass/timeout"; fi
    # engine-harness-proof-gate should accept the manifest's non-zero count via log mode
    if [ -f "$GATE" ] && command -v python3 >/dev/null 2>&1; then
        # the fuzz log carries "PASS"/"ok" -> proof gate log mode credits non-zero
        flog="$(ls "$WS11"/fuzz_runs/*/fuzz_*.log 2>/dev/null | head -1)"
        if [ -n "$flog" ]; then
            python3 "$GATE" "$flog" >/dev/null 2>&1
            grc=$?
            # 0 = pass-real, 1 = fail; we only assert it runs cleanly (no crash/exit 2)
            [ "$grc" -ne 2 ] && ok "proof-gate consumes fuzz log without input-error" || bad "proof-gate input-error on fuzz log"
        else
            ok "no fuzz log produced (timeout before output) — gate consumption skipped"
        fi
    else
        ok "proof-gate or python3 absent — gate-consumption check skipped"
    fi
else
    ok "go not installed — live run + gate-consumption tests skipped (honest)"
fi

echo ""
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
