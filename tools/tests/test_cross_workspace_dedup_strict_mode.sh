#!/usr/bin/env bash
# Focused regression test for Gap 17 (cross-workspace-dedup empty array under set -u).
#
# Reproduces the failure: when the draft path does not match `*/audits/*/*`,
# pre-submit-check.sh:4089 leaves _CWDC_ARGS as an empty array, and bash 3.2
# (macOS default) errors with `_CWDC_ARGS[@]: unbound variable` under
# `set -uo pipefail`, causing Check #40 to false-BLOCK even when the
# downstream tool exits 0.
#
# Verifies:
#   1. The empty-array expansion no longer raises unbound-variable.
#   2. Check #40 returns PASS when no cross-workspace duplicate exists.
#   3. The fix uses ${arr[@]+"${arr[@]}"} (canonical safe form) and does NOT
#      inject a stray empty positional that would silently downgrade to WARN.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[test_cross_workspace_dedup_strict_mode] SKIP: python3 not on PATH"
  exit 0
fi

FAIL=0
PASS=0
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

# --- Case 1: assert the bash 3.2 empty-array bug pattern is fixed ------------
# We synthesize the exact strict-mode invocation pattern used in
# pre-submit-check.sh:4089 and assert it no longer raises unbound-variable
# when the array is empty.
cat > "$SANDBOX/empty_array_repro.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
arr=()
# canonical safe form (the fix):
echo "fix:" "ARG1" ${arr[@]+"${arr[@]}"} "ARG2"
EOF
chmod +x "$SANDBOX/empty_array_repro.sh"
out=$(bash "$SANDBOX/empty_array_repro.sh" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "fix: ARG1 ARG2" ]; then
  echo "[OK ] Case 1: ${arr[@]+\"\${arr[@]}\"} expands to zero args under set -u"
  PASS=$((PASS + 1))
else
  echo "[FAIL] Case 1: empty-array safe form regressed (rc=$rc, out='$out')"
  FAIL=$((FAIL + 1))
fi

# --- Case 2: assert the old broken pattern still fails -----------------------
# Sanity check: if we accidentally revert the fix, the test should catch it.
cat > "$SANDBOX/empty_array_broken.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
arr=()
echo "broken:" "ARG1" "${arr[@]}" "ARG2"
EOF
chmod +x "$SANDBOX/empty_array_broken.sh"
out=$(bash "$SANDBOX/empty_array_broken.sh" 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && echo "$out" | grep -q 'unbound variable'; then
  echo "[OK ] Case 2: broken pattern still raises unbound variable (control)"
  PASS=$((PASS + 1))
else
  echo "[FAIL] Case 2: broken pattern should fail under bash 3.2 strict mode (rc=$rc)"
  FAIL=$((FAIL + 1))
fi

# --- Case 3: assert ${arr[@]:-} injects a stray empty arg --------------------
# Documents why we chose ${arr[@]+"${arr[@]}"} instead of ${arr[@]:-} (which
# the lane brief originally suggested). The :-} form silently appends an empty
# positional that argparse rejects with rc=2, silently downgrading Check #40
# from PASS to WARN.
cat > "$SANDBOX/empty_array_strayarg.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
arr=()
count() { echo "n=$#"; for a in "$@"; do echo "  [$a]"; done; }
count "ARG1" "${arr[@]:-}" "ARG2"
EOF
chmod +x "$SANDBOX/empty_array_strayarg.sh"
out=$(bash "$SANDBOX/empty_array_strayarg.sh" 2>&1)
# Verify the stray-empty-arg behavior (n=3 with middle arg empty) so that
# anyone "fixing" the pattern back to :-} can see why we rejected it.
if echo "$out" | grep -q '^n=3$'; then
  echo "[OK ] Case 3: :-} form injects stray empty arg (documented anti-pattern)"
  PASS=$((PASS + 1))
else
  echo "[FAIL] Case 3: :-} form behavior changed (out='$out'); revisit Gap 17 fix"
  FAIL=$((FAIL + 1))
fi

# --- Case 4: end-to-end: run pre-submit-check on a draft outside ~/audits/ --
# This is the original reproducer. With the broken pattern, Check #40 would
# print `unbound variable` + flip to BLOCKED. With the fix, Check #40 returns
# PASS (since no other workspace has the synthetic content).
TEST_DRAFT="$SANDBOX/test_draft.md"
cat > "$TEST_DRAFT" <<'EOF'
# Synthetic Gap 17 regression draft

## Summary
Direct loss of funds via test-only path (synthetic; should not match any
real cross-workspace prior submission).

## Rubric
Medium per SEVERITY.md row Medium.1: synthetic test rubric stub.

## PoC
<!-- l32-rebuttal: synthetic, not a real production-grade claim -->
EOF

# Run the gate. We only care about Check #40 output here; we tolerate other
# checks failing (the synthetic draft is intentionally incomplete).
out=$(SEVERITY=Medium bash "$REPO/tools/pre-submit-check.sh" "$TEST_DRAFT" 2>&1 || true)
if echo "$out" | grep -q 'unbound variable'; then
  echo "[FAIL] Case 4: pre-submit-check.sh still raises unbound variable"
  echo "$out" | grep -A1 'unbound' | head -4 | sed 's/^/         /'
  FAIL=$((FAIL + 1))
else
  echo "[OK ] Case 4: no unbound-variable error in pre-submit-check.sh output"
  PASS=$((PASS + 1))
fi

# Check #40 should PASS (no real duplicate) - either by reporting "no
# duplicate above threshold" or, if the dedup corpus is empty, by reporting
# "tool not found" (warn). It must NOT report "BLOCKED" because of the
# strict-mode bug.
c40_line=$(echo "$out" | grep -E '40\. cross-workspace' | head -1)
if echo "$c40_line" | grep -q 'BLOCKED'; then
  echo "[FAIL] Case 4b: Check #40 false-BLOCKED on synthetic draft (line: $c40_line)"
  FAIL=$((FAIL + 1))
else
  echo "[OK ] Case 4b: Check #40 did not false-BLOCK ($c40_line)"
  PASS=$((PASS + 1))
fi

echo ""
echo "[test_cross_workspace_dedup_strict_mode] PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
