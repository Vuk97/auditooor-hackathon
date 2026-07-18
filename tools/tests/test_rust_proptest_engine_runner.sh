#!/usr/bin/env bash
# test_rust_proptest_engine_runner.sh — tests for the Rust dynamic-engine adapter.
#
# These tests run WITHOUT a real cargo build (fast, hermetic). They exercise:
#   1. missing-workspace -> exit 2
#   2. no-Cargo.toml workspace -> status=skipped, manifest emitted, exit 0
#   3. feature discovery from [features] -> correct -p packages in command
#   4. dry-run -> command rendered, no cargo invocation, exit 0
#   5. manifest schema fields present + valid JSON
#   6. timeout cap enforced (5401 -> 5400)

set -uo pipefail
RUNNER="$(cd "$(dirname "$0")/.." && pwd)/rust-proptest-engine-runner.sh"
PASS=0; FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL - $1"; FAIL=$((FAIL+1)); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- Test 1: missing workspace -> exit 2 -------------------------------------
bash "$RUNNER" "$TMP/does-not-exist" >/dev/null 2>&1
[ $? -eq 2 ] && ok "missing-workspace exits 2" || bad "missing-workspace should exit 2"

# --- Test 2: workspace with no Cargo.toml -> skipped, manifest emitted --------
WS2="$TMP/ws_no_cargo"; mkdir -p "$WS2"
out2="$(bash "$RUNNER" "$WS2" 2>&1)"; rc2=$?
[ $rc2 -eq 0 ] && ok "no-Cargo exits 0" || bad "no-Cargo should exit 0 (got $rc2)"
man2="$(ls "$WS2"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
if [ -n "$man2" ] && grep -q '"status": "skipped"' "$man2"; then ok "no-Cargo status=skipped"; else bad "no-Cargo manifest missing/not-skipped"; fi
grep -q 'no Cargo.toml' "$man2" 2>/dev/null && ok "no-Cargo notes explain reason" || bad "no-Cargo notes missing reason"

# --- Test 3 + 4: feature discovery + dry-run command render -------------------
WS3="$TMP/ws_cargo"; mkdir -p "$WS3/crate-a/src" "$WS3/crate-b/src"
cat > "$WS3/Cargo.toml" <<'EOF'
[workspace]
members = ["crate-a", "crate-b"]
EOF
# crate-a declares proptest-impl; crate-b does NOT
cat > "$WS3/crate-a/Cargo.toml" <<'EOF'
[package]
name = "crate-a"
version = "0.1.0"
[features]
proptest-impl = ["proptest"]
EOF
echo 'fn main(){}' > "$WS3/crate-a/src/lib.rs"
cat > "$WS3/crate-b/Cargo.toml" <<'EOF'
[package]
name = "crate-b"
version = "0.1.0"
EOF
echo 'fn main(){}' > "$WS3/crate-b/src/lib.rs"

out3="$(bash "$RUNNER" "$WS3" --dry-run 2>&1)"; rc3=$?
[ $rc3 -eq 0 ] && ok "dry-run exits 0" || bad "dry-run should exit 0 (got $rc3)"
cmd3="$(ls "$WS3"/fuzz_runs/*/command.txt 2>/dev/null | head -1)"
if grep -q '\-p crate-a' "$cmd3" 2>/dev/null; then ok "discovered crate-a (has proptest-impl)"; else bad "should discover crate-a"; fi
if grep -q '\-p crate-b' "$cmd3" 2>/dev/null; then bad "should NOT discover crate-b (no proptest-impl)"; else ok "skipped crate-b (no proptest-impl)"; fi
grep -q 'cargo test' "$cmd3" 2>/dev/null && ok "command uses cargo test" || bad "command should use cargo test"
grep -q 'features proptest-impl' "$cmd3" 2>/dev/null && ok "command passes --features proptest-impl" || bad "command should pass feature"
grep -q '\-\- prop' "$cmd3" 2>/dev/null && ok "command defaults filter to 'prop'" || bad "command should filter prop"

# --- Test 5: manifest schema fields + valid JSON ------------------------------
man3="$(ls "$WS3"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['engine']=='rust-proptest'; assert 'status' in d; assert 'counterexample_path' in d; assert d['schema_version']==1; assert 'proptest_cases' in d" "$man3" 2>/dev/null; then
        ok "manifest is valid JSON with required fields"
    else bad "manifest JSON invalid or missing fields"; fi
else ok "python3 absent — skip JSON validation"; fi

# --- Test 6: timeout cap (5401 -> 5400) ---------------------------------------
WS6="$TMP/ws_cap"; mkdir -p "$WS6"
bash "$RUNNER" "$WS6" --timeout 5401 >/dev/null 2>&1
man6="$(ls "$WS6"/fuzz_runs/*/manifest.json 2>/dev/null | head -1)"
if grep -q '"timeout_seconds": 5400' "$man6" 2>/dev/null; then ok "timeout capped at 5400"; else bad "timeout should cap at 5400"; fi

# --- Test 7: --feature "" opts out of discovery (whole workspace) -------------
out7="$(bash "$RUNNER" "$WS3" --feature "" --dry-run 2>&1)"
cmd7="$(ls -t "$WS3"/fuzz_runs/*/command.txt 2>/dev/null | head -1)"
grep -q '\-\-workspace' "$cmd7" 2>/dev/null && ok "empty-feature runs --workspace" || bad "empty-feature should run --workspace"

echo ""
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
