#!/usr/bin/env bash
# test_audit_deep_pillar_wiring.sh — regression test for WF-4 patches A/B/C/E/F/G/H
# wired into tools/audit-deep.sh and Makefile audit-deep-solidity recipe.
#
# Patches under test:
#   Patch A: R37 verification-tier audit wired into audit-deep
#   Patch B: regex-detectors wired into audit-deep (guarded by SKIP_REGEX=1)
#   Patch C: wave14 Slither AST custom detectors wired into audit-deep-solidity
#   Patch E: typed-candidate-promotion banner repositioned to TOP of report
#   Patch F: Hunter Handoff artifact section emitted in audit-deep report
#   Patch G: audit-deep-medium bounded live profile wired
#   Patch H: detector smoke unit-tests stitched into audit-deep report
#
# Assertions:
#   1. SKIP_REGEX=1 path: audit-deep dry-run skips regex-detectors cleanly.
#   2. R37 audit step is invoked (mock invocation in DRY_RUN; helper present
#      in audit-deep.sh source).
#   3. Wave14 Slither AST step exists in Solidity branch (grep Makefile).
#   4. Typed-candidate-promotion banner appears at the TOP of the report
#      (within the first 50 lines, just below the tool-availability table).
#   5. Hunter Handoff section includes detector-arsenal + R37 artifact keys.
#   6. Medium profile emits a medium report and Makefile target exists.
#   7. Detector smoke unit-test section is reported and handoff-linked.
#   8. Skip-prereq path has an explicit freshness gate / stale override.
#
# Skips cleanly if bash/make/python3 are unavailable. No network.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if ! command -v bash >/dev/null 2>&1; then
  echo "[test_audit_deep_pillar_wiring] SKIP: bash not on PATH"; exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[test_audit_deep_pillar_wiring] SKIP: python3 not on PATH"; exit 0
fi

FAIL=0
PASS=0

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
WS="$SANDBOX/audits/wf4-wiring-test"
mkdir -p "$WS/.audit_logs" "$WS/.auditooor"

# Seed a typed_candidate_promotions.json so Patch E has a real count to read.
cat > "$WS/.audit_logs/typed_candidate_promotions.json" <<'EOF'
{
  "blocker_counts": {},
  "candidate_count": 3,
  "decision_counts": {
    "impact_unresolved": 0,
    "needs_poc": 2,
    "poc_ready": 1,
    "rejected": 0
  },
  "schema_version": "auditooor.promote_typed_candidate.v1",
  "verdicts": [],
  "work_items": [
    {"lane": "L1", "decision": "poc_ready"},
    {"lane": "L2", "decision": "needs_poc"},
    {"lane": "L3", "decision": "needs_poc"}
  ],
  "workspace": "WS_PATH_PLACEHOLDER"
}
EOF

# --- Test 1: SKIP_REGEX=1 cleanly skips Patch B step ------------------------
out="$(SKIP_REGEX=1 AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS" 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: SKIP_REGEX=1 + dry-run exits 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: SKIP_REGEX=1 + dry-run exit=$rc"
  echo "----- stdout -----"
  echo "$out" | tail -30
  echo "------------------"
fi

REPORT="$WS/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT" ] && grep -q "Regex detector arsenal" "$REPORT" && \
   grep -q "SKIP_REGEX=1\|regex-detectors (SKIP_REGEX=1)" "$REPORT"; then
  PASS=$((PASS+1))
  echo "PASS: Patch B regex-detectors section present + SKIP_REGEX=1 honored"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch B section missing or SKIP_REGEX=1 not honored in report"
  if [ -f "$REPORT" ]; then
    echo "----- report tail -----"
    tail -40 "$REPORT"
    echo "-----------------------"
  fi
fi

# --- Test 2: R37 audit step is invoked (Patch A) ----------------------------
if [ -f "$REPORT" ] && grep -q "R37 verification-tier audit" "$REPORT"; then
  PASS=$((PASS+1))
  echo "PASS: Patch A R37 verification-tier audit section present"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch A R37 audit section missing from report"
fi

# Also confirm the helper function is defined in audit-deep.sh source.
if grep -q "^run_r37_audit()" "$REPO/tools/audit-deep.sh"; then
  PASS=$((PASS+1))
  echo "PASS: run_r37_audit() helper defined in audit-deep.sh"
else
  FAIL=$((FAIL+1))
  echo "FAIL: run_r37_audit() helper missing from audit-deep.sh"
fi

if grep -q "^run_regex_detectors()" "$REPO/tools/audit-deep.sh"; then
  PASS=$((PASS+1))
  echo "PASS: run_regex_detectors() helper defined in audit-deep.sh"
else
  FAIL=$((FAIL+1))
  echo "FAIL: run_regex_detectors() helper missing from audit-deep.sh"
fi

# --- Test 3: Wave14 Slither AST step exists in Solidity branch (Patch C) ----
if grep -q 'run_step "wave14-slither-ast"' "$REPO/Makefile" && \
   grep -q 'detectors/run_custom.py' "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Patch C wave14-slither-ast step wired into Makefile audit-deep-solidity"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch C wave14-slither-ast wiring missing from Makefile"
fi

# Confirm it sits in the order list too.
if grep -q '"wave14-slither-ast"' "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Patch C wave14-slither-ast present in aggregator order list"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch C wave14-slither-ast missing from aggregator order list"
fi

# --- Test 4: Patch E typed-candidate-promotion banner at TOP of report ------
# Re-run audit-deep so the banner emitter has a fresh report to prepend to.
WS2="$SANDBOX/audits/wf4-patch-e-test"
mkdir -p "$WS2/.audit_logs"
# Seed BOTH the typed_candidate_promotions.json (so banner shows non-zero
# count) AND a per-profile report stub so the emitter has something to
# prepend into.
cat > "$WS2/.audit_logs/typed_candidate_promotions.json" <<EOF
{
  "candidate_count": 7,
  "decision_counts": {"poc_ready": 2, "needs_poc": 5},
  "schema_version": "auditooor.promote_typed_candidate.v1"
}
EOF

out2="$(SKIP_REGEX=1 AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS2" 2>&1)"
rc2=$?
if [ "$rc2" -ne 0 ]; then
  FAIL=$((FAIL+1))
  echo "FAIL: Patch E test dry-run exit=$rc2"
  echo "$out2" | tail -20
fi

REPORT2="$WS2/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT2" ]; then
  # Check banner appears in first 50 lines (TOP of report).
  if head -50 "$REPORT2" | grep -q "TYPED CANDIDATE PROMOTION QUEUE (WF-4 Patch E)"; then
    PASS=$((PASS+1))
    echo "PASS: Patch E banner appears within first 50 lines of report"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: Patch E banner not in first 50 lines"
    echo "----- first 50 lines -----"
    head -50 "$REPORT2"
    echo "--------------------------"
  fi

  # Check the count key is rendered. The exact value may be overwritten by
  # run_cross_lane_correlate -> promote-typed-candidate at runtime.
  if grep -q "candidate-count:" "$REPORT2"; then
    PASS=$((PASS+1))
    echo "PASS: Patch E banner renders candidate-count key"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: Patch E banner missing candidate-count key"
  fi

  # Check operator guidance line exists for both non-zero and zero queues.
  if grep -Eq "review these [0-9]+ candidates first|no typed candidates promoted this run" "$REPORT2"; then
    PASS=$((PASS+1))
    echo "PASS: Patch E banner emits queue guidance line"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: Patch E banner missing queue guidance line"
  fi
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch E test report not created"
fi

# --- Test 5: Patch F hunter handoff artifact section exists -----------------
if [ -f "$REPORT2" ] && grep -q "## Hunter Handoff (WF-4 Patch F)" "$REPORT2" && \
   grep -q "detector-arsenal-status:" "$REPORT2" && \
   grep -q "detector-arsenal-manifest:" "$REPORT2" && \
   grep -q "r37-tier-audit-status:" "$REPORT2"; then
  PASS=$((PASS+1))
  echo "PASS: Patch F Hunter Handoff section present with detector/R37 artifact keys"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch F Hunter Handoff section missing or incomplete"
  if [ -f "$REPORT2" ]; then
    echo "----- Hunter Handoff grep -----"
    grep -n "Hunter Handoff\|detector-arsenal-\|r37-tier-audit-" "$REPORT2" || true
    echo "-------------------------------"
  fi
fi

# --- Test 6: emit_typed_candidate_promotion_banner is idempotent ------------
# Run the audit-deep one more time and confirm the banner doesn't double-emit.
out3="$(SKIP_REGEX=1 AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS2" 2>&1)"
rc3=$?
banner_count="$(grep -c "TYPED CANDIDATE PROMOTION QUEUE (WF-4 Patch E)" "$REPORT2" 2>/dev/null || echo 0)"
if [ "$rc3" -eq 0 ] && [ "$banner_count" = "1" ]; then
  PASS=$((PASS+1))
  echo "PASS: Patch E banner remains idempotent (count=1 after second invocation on the canonical report)"
else
  # A new per-invocation file is created each run, so we accept the
  # canonical symlink target reflecting the LATEST invocation only.
  # Confirm at minimum that the latest file has exactly one banner.
  latest="$(ls -t "$WS2/.audit_logs"/audit_deep_default_*.md 2>/dev/null | head -1)"
  if [ -n "$latest" ]; then
    latest_count="$(grep -c "TYPED CANDIDATE PROMOTION QUEUE (WF-4 Patch E)" "$latest" 2>/dev/null || echo 0)"
    if [ "$rc3" -eq 0 ] && [ "$latest_count" = "1" ]; then
      PASS=$((PASS+1))
      echo "PASS: Patch E banner is idempotent on the latest per-profile report (count=1)"
    else
      FAIL=$((FAIL+1))
      echo "FAIL: Patch E banner non-idempotent — latest=$latest_count"
    fi
  else
    FAIL=$((FAIL+1))
    echo "FAIL: Patch E banner idempotence check could not locate per-profile report"
  fi
fi

# --- Test 7: Patch G medium profile + target wiring ------------------------
WS_MED="$SANDBOX/audits/wf4-medium-profile-test"
mkdir -p "$WS_MED"
out_med="$(SKIP_REGEX=1 AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run --profile medium "$WS_MED" 2>&1)"
rc_med=$?
REPORT_MED="$WS_MED/.audit_logs/audit_deep_report.md"
if [ "$rc_med" -eq 0 ] && [ -f "$REPORT_MED" ] && \
   grep -q "profile: medium" "$REPORT_MED" && \
   grep -q "medium bounds:" "$REPORT_MED" && \
   ls "$WS_MED/.audit_logs"/audit_deep_medium_*.md >/dev/null 2>&1; then
  PASS=$((PASS+1))
  echo "PASS: Patch G --profile medium emits bounded medium report"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch G --profile medium report missing or malformed"
  echo "----- output -----"
  echo "$out_med" | tail -30
  echo "----- report -----"
  [ -f "$REPORT_MED" ] && head -40 "$REPORT_MED"
  echo "------------------"
fi

if grep -q "^audit-deep-medium:" "$REPO/Makefile" && \
   grep -q "DEEP_PROFILE=medium" "$REPO/Makefile" && \
   grep -q "LIVE=1" "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Patch G Makefile audit-deep-medium target is wired"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch G Makefile audit-deep-medium target missing"
fi

# --- Test 8: Patch H detector smoke unit-test stitch -----------------------
if [ -f "$REPORT2" ] && grep -q "## Detector smoke unit tests (WF-4 Patch H)" "$REPORT2" && \
   grep -q "planned-command: .*tools.tests.test_run_detector tools.tests.test_inventory_smoke_test" "$REPORT2" && \
   grep -q "detector-smoke-unit-tests (DRY_RUN=1)" "$REPORT2"; then
  PASS=$((PASS+1))
  echo "PASS: Patch H detector smoke unit-test section appears in report summary"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch H detector smoke unit-test section missing"
  [ -f "$REPORT2" ] && grep -n "Detector smoke\|detector-smoke" "$REPORT2" || true
fi

if [ -f "$REPORT2" ] && grep -q "detector-smoke-unit-tests-status:" "$REPORT2" && \
   grep -q "detector-smoke-unit-tests-log:" "$REPORT2"; then
  PASS=$((PASS+1))
  echo "PASS: Patch H detector smoke artifacts are included in Hunter Handoff"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch H Hunter Handoff detector smoke artifact keys missing"
fi

# --- Test 9: Patch D skip-prereq freshness gate is discoverable ------------
if grep -q "AUDIT_DEEP_ALLOW_STALE_AUDIT_PREREQ" "$REPO/Makefile" && \
   grep -q "freshness gate: PASS" "$REPO/Makefile" && \
   grep -q "requires fresh audit_completion.json" "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Patch D skip-prereq path has freshness gate and explicit stale override"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Patch D freshness gate missing from Makefile audit-deep recipe"
fi

echo ""
echo "[test_audit_deep_pillar_wiring] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
