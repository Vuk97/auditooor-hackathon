#!/usr/bin/env bash
# test_audit_deep_rust_wiring.sh — regression test for Wave 3 Rust wiring of
# `tools/audit-deep.sh` Steps 6 (anchor backend), 7 (rust source graph) and
# 8 (rust cross-crate graph).
#
# Assertions:
#   1. Empty workspace: all 3 new steps self-skip with
#      "no Rust workspace detected" and audit-deep still exits 0.
#   2. Synthetic single-crate Cargo workspace:
#        - Step 7 (rust-source-graph) RUNS  (or DRY_RUN-skips with planned cmd).
#        - Step 8 (rust-cross-crate-graph) self-skips with single-crate reason.
#        - Step 6 (anchor) self-skips (no anchor-lang, no programs/<crate>/src).
#   3. Synthetic 2-crate Cargo workspace ([workspace] manifest):
#        - Step 7 RUNS.
#        - Step 8 RUNS.
#   4. Synthetic Anchor workspace (anchor-lang dep + programs/foo/src/lib.rs):
#        - Step 6 RUNS.
#        - Step 7 RUNS.
#
# All assertions use DRY_RUN to keep the test fast and offline. The script
# only checks that the planned command is logged and the step did not
# self-skip. Real execution is exercised by each runner's own test
# (test_anchor_detector_runner.py / test_rust_source_graph.py /
# test_rust_cross_crate_graph.py).
#
# Skips cleanly if bash/python3 are unavailable. No network.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if ! command -v bash >/dev/null 2>&1; then
  echo "[test_audit_deep_rust_wiring] SKIP: bash not on PATH"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[test_audit_deep_rust_wiring] SKIP: python3 not on PATH"
  exit 0
fi

FAIL=0
PASS=0

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

run_audit_deep() {
    # $1 = workspace path
    AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$1" >/dev/null 2>&1
    return $?
}

extract_section() {
    # Extract the section starting at "### Step <N>" up to (but not
    # including) the next "### Step " or "## " header. Stdlib awk only.
    local report="$1" step="$2"
    awk -v hdr="### Step ${step} " '
        index($0, hdr) == 1 {flag=1; next}
        flag && (index($0, "### Step ") == 1 || index($0, "## ") == 1) {flag=0}
        flag {print}
    ' "$report"
}

assert_step_skipped() {
    local report="$1" step="$2" reason="$3" label="$4"
    local section
    section=$(extract_section "$report" "$step")
    if echo "$section" | grep -qF "skipped: $reason"; then
        PASS=$((PASS+1))
        echo "PASS: $label — Step $step skipped with '$reason'"
    else
        FAIL=$((FAIL+1))
        echo "FAIL: $label — Step $step missing 'skipped: $reason'"
        echo "----- section -----"
        echo "$section"
        echo "-------------------"
    fi
}

assert_step_ran_or_planned() {
    local report="$1" step="$2" label="$3"
    local section
    section=$(extract_section "$report" "$step")
    # Either "- ran:" or "- planned:" (DRY_RUN). Must NOT contain
    # "no Rust workspace detected" or "single-crate workspace".
    if (echo "$section" | grep -qE "^- (ran|planned):") && \
       ! echo "$section" | grep -qE "no Rust workspace detected|single-crate workspace"; then
        PASS=$((PASS+1))
        echo "PASS: $label — Step $step ran/planned"
    else
        FAIL=$((FAIL+1))
        echo "FAIL: $label — Step $step did not run/plan"
        echo "----- section -----"
        echo "$section"
        echo "-------------------"
    fi
}

# ---------------------------------------------------------------------------
# Case 1: empty workspace -> all 3 new steps self-skip.
# ---------------------------------------------------------------------------
WS1="$SANDBOX/empty"
mkdir -p "$WS1"
run_audit_deep "$WS1"
rc1=$?
REPORT1="$WS1/.audit_logs/audit_deep_report.md"
if [ "$rc1" -eq 0 ] && [ -f "$REPORT1" ]; then
    PASS=$((PASS+1))
    echo "PASS: empty workspace — audit-deep exits 0 with report"
else
    FAIL=$((FAIL+1))
    echo "FAIL: empty workspace — exit=$rc1 report=$REPORT1"
fi
assert_step_skipped "$REPORT1" "6" "no Rust workspace detected" "empty workspace"
assert_step_skipped "$REPORT1" "7" "no Rust workspace detected" "empty workspace"
assert_step_skipped "$REPORT1" "8" "no Rust workspace detected" "empty workspace"

# ---------------------------------------------------------------------------
# Case 2: single-crate Cargo workspace.
# Layout:
#   <ws>/Cargo.toml          (no [workspace] table)
#   <ws>/src/lib.rs
# Expected: Step 7 plans, Step 8 self-skips with single-crate reason,
# Step 6 self-skips (no anchor).
# ---------------------------------------------------------------------------
WS2="$SANDBOX/single-crate"
mkdir -p "$WS2/src"
cat >"$WS2/Cargo.toml" <<'EOF'
[package]
name = "single_demo"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
EOF
echo 'pub fn hello() {}' >"$WS2/src/lib.rs"

run_audit_deep "$WS2"
rc2=$?
REPORT2="$WS2/.audit_logs/audit_deep_report.md"
if [ "$rc2" -eq 0 ] && [ -f "$REPORT2" ]; then
    PASS=$((PASS+1))
    echo "PASS: single-crate workspace — audit-deep exits 0"
else
    FAIL=$((FAIL+1))
    echo "FAIL: single-crate workspace — exit=$rc2"
fi
assert_step_skipped "$REPORT2" "6" "no Rust workspace detected" "single-crate"
assert_step_ran_or_planned "$REPORT2" "7" "single-crate"
assert_step_skipped "$REPORT2" "8" "single-crate workspace (Step 7 covers this)" "single-crate"

# ---------------------------------------------------------------------------
# Case 3: 2-crate Cargo workspace.
# Layout:
#   <ws>/Cargo.toml          ([workspace] members = ["crates/a","crates/b"])
#   <ws>/crates/a/Cargo.toml
#   <ws>/crates/a/src/lib.rs
#   <ws>/crates/b/Cargo.toml
#   <ws>/crates/b/src/lib.rs
# Expected: Steps 7 + 8 both run/plan, Step 6 skips (no anchor).
# ---------------------------------------------------------------------------
WS3="$SANDBOX/multi-crate"
mkdir -p "$WS3/crates/a/src" "$WS3/crates/b/src"
cat >"$WS3/Cargo.toml" <<'EOF'
[workspace]
members = ["crates/a", "crates/b"]
EOF
cat >"$WS3/crates/a/Cargo.toml" <<'EOF'
[package]
name = "crate_a"
version = "0.1.0"
edition = "2021"

[dependencies]
crate_b = { path = "../b" }
EOF
echo 'pub fn a() {}' >"$WS3/crates/a/src/lib.rs"
cat >"$WS3/crates/b/Cargo.toml" <<'EOF'
[package]
name = "crate_b"
version = "0.1.0"
edition = "2021"
EOF
echo 'pub fn b() {}' >"$WS3/crates/b/src/lib.rs"

run_audit_deep "$WS3"
rc3=$?
REPORT3="$WS3/.audit_logs/audit_deep_report.md"
if [ "$rc3" -eq 0 ] && [ -f "$REPORT3" ]; then
    PASS=$((PASS+1))
    echo "PASS: multi-crate workspace — audit-deep exits 0"
else
    FAIL=$((FAIL+1))
    echo "FAIL: multi-crate workspace — exit=$rc3"
fi
assert_step_skipped "$REPORT3" "6" "no Rust workspace detected" "multi-crate"
assert_step_ran_or_planned "$REPORT3" "7" "multi-crate"
assert_step_ran_or_planned "$REPORT3" "8" "multi-crate"

# ---------------------------------------------------------------------------
# Case 4: Anchor workspace.
# Layout:
#   <ws>/Cargo.toml          (anchor-lang = "0.30")
#   <ws>/programs/foo/Cargo.toml
#   <ws>/programs/foo/src/lib.rs
# Expected: Step 6 runs/plans, Step 7 also runs (rs files + Cargo.toml),
# Step 8 may skip if not multi-crate enough — we don't assert it here.
# ---------------------------------------------------------------------------
WS4="$SANDBOX/anchor-ws"
mkdir -p "$WS4/programs/foo/src"
cat >"$WS4/Cargo.toml" <<'EOF'
[package]
name = "anchor_demo"
version = "0.1.0"
edition = "2021"

[dependencies]
anchor-lang = "0.30"
EOF
cat >"$WS4/programs/foo/Cargo.toml" <<'EOF'
[package]
name = "foo"
version = "0.1.0"
edition = "2021"

[dependencies]
anchor-lang = "0.30"
EOF
cat >"$WS4/programs/foo/src/lib.rs" <<'EOF'
use anchor_lang::prelude::*;

#[program]
pub mod foo {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }
}

#[derive(Accounts)]
pub struct Initialize {}
EOF

run_audit_deep "$WS4"
rc4=$?
REPORT4="$WS4/.audit_logs/audit_deep_report.md"
if [ "$rc4" -eq 0 ] && [ -f "$REPORT4" ]; then
    PASS=$((PASS+1))
    echo "PASS: anchor workspace — audit-deep exits 0"
else
    FAIL=$((FAIL+1))
    echo "FAIL: anchor workspace — exit=$rc4"
fi
assert_step_ran_or_planned "$REPORT4" "6" "anchor"
assert_step_ran_or_planned "$REPORT4" "7" "anchor"

# ---------------------------------------------------------------------------
# Case 5: declared rc28-clean Rust root gets named graph artifacts.
# Layout:
#   <ws>/.auditooor/project_source_root_readiness.json
#   <ws>/external/base-rc28-clean/crates/a/src/lib.rs
#   <ws>/external/base-rc28-clean/crates/b/src/lib.rs
# Expected: default graph commands remain planned, and Step 7/8 also plan
# named rc28-clean artifacts so handoffs do not require manual graph copying.
# ---------------------------------------------------------------------------
WS5="$SANDBOX/declared-rc28-root"
mkdir -p "$WS5/.auditooor" \
         "$WS5/external/base-rc28-clean/crates/a/src" \
         "$WS5/external/base-rc28-clean/crates/b/src"
cat >"$WS5/external/base-rc28-clean/Cargo.toml" <<'EOF'
[workspace]
members = ["crates/a", "crates/b"]
EOF
cat >"$WS5/external/base-rc28-clean/crates/a/Cargo.toml" <<'EOF'
[package]
name = "rc28_a"
version = "0.1.0"
edition = "2021"

[dependencies]
rc28_b = { path = "../b" }
EOF
echo 'pub fn a() {}' >"$WS5/external/base-rc28-clean/crates/a/src/lib.rs"
cat >"$WS5/external/base-rc28-clean/crates/b/Cargo.toml" <<'EOF'
[package]
name = "rc28_b"
version = "0.1.0"
edition = "2021"
EOF
echo 'pub fn b() {}' >"$WS5/external/base-rc28-clean/crates/b/src/lib.rs"
cat >"$WS5/.auditooor/project_source_root_readiness.json" <<EOF
{
  "roots": [
    {
      "declared_path": "external/base-rc28-clean",
      "resolved_path": "$WS5/external/base-rc28-clean",
      "language_presence": {"rust": 2},
      "rejection_reasons": []
    }
  ]
}
EOF

run_audit_deep "$WS5"
rc5=$?
REPORT5="$WS5/.audit_logs/audit_deep_report.md"
if [ "$rc5" -eq 0 ] && [ -f "$REPORT5" ]; then
    PASS=$((PASS+1))
    echo "PASS: declared rc28 root — audit-deep exits 0"
else
    FAIL=$((FAIL+1))
    echo "FAIL: declared rc28 root — exit=$rc5"
fi
section7=$(extract_section "$REPORT5" "7")
if echo "$section7" | grep -q "rust_source_graph.rc28-clean.json" && \
   echo "$section7" | grep -q "external/base-rc28-clean"; then
    PASS=$((PASS+1))
    echo "PASS: declared rc28 root — Step 7 plans named source graph"
else
    FAIL=$((FAIL+1))
    echo "FAIL: declared rc28 root — Step 7 missing named source graph plan"
    echo "----- section -----"
    echo "$section7"
    echo "-------------------"
fi
section8=$(extract_section "$REPORT5" "8")
if echo "$section8" | grep -q "rust_cross_crate_graph.rc28-clean.json" && \
   echo "$section8" | grep -q "external/base-rc28-clean"; then
    PASS=$((PASS+1))
    echo "PASS: declared rc28 root — Step 8 plans named cross-crate graph"
else
    FAIL=$((FAIL+1))
    echo "FAIL: declared rc28 root — Step 8 missing named cross-crate graph plan"
    echo "----- section -----"
    echo "$section8"
    echo "-------------------"
fi
if grep -q "declared Rust root graph (rc28-clean from external/base-rc28-clean)" "$REPORT5"; then
    PASS=$((PASS+1))
    echo "PASS: declared rc28 root — summary points at named graph"
else
    FAIL=$((FAIL+1))
    echo "FAIL: declared rc28 root — summary missing named graph pointer"
fi

echo ""
echo "[test_audit_deep_rust_wiring] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
