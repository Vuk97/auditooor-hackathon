#!/usr/bin/env bash
# test_audit_deep_candidate_adjudicator_wiring.sh
#
# Wires-FIX-1 + FIX-2 regression test. Asserts that tools/audit-deep.sh runs the
# two candidate ADJUDICATORS so produced candidates actually get verdicted:
#
#   FIX 1 (validate-deep-candidate.py): each deep_candidate.v1 record under
#     <ws>/deep_candidates/*.json is run through the schema + V5 advisory-floor
#     validator and a kept/killed verdict recorded to
#     <ws>/.audit_logs/deep_candidate_adjudication.json.
#
#   FIX 2 (adversarial-candidate-verify.py): Medium+ candidates from the deep
#     lane AND the exploit queue (<ws>/.auditooor/exploit_queue.json rows) are
#     run through the 3-lens refutation panel and the survived/refuted verdict
#     recorded to <ws>/.audit_logs/adversarial_candidate_verify.json.
#
# Checks:
#   1. Both adjudicator stages are PRESENT (functions defined + called) in
#      audit-deep.sh.
#   2. On an empty workspace, both stages SKIP cleanly (rc=0, no crash).
#   3. On a workspace with a synthetic VALID + synthetic INVALID deep candidate
#      and an exploit_queue with a critical + a low row, the run records:
#        - deep adjudication: 2 candidates, 1 kept, 1 killed
#        - adversarial panel: the critical exploit_queue row is verdicted
#          (Medium+ fired) and the low row skipped.
#
# stdlib-only. Skips gracefully if bash/python3 are missing.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TOOL="$REPO/tools/audit-deep.sh"

if ! command -v bash >/dev/null 2>&1; then
  echo "[test_audit_deep_candidate_adjudicator_wiring] SKIP: bash missing"; exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[test_audit_deep_candidate_adjudicator_wiring] SKIP: python3 missing"; exit 0
fi
if [ ! -f "$TOOL" ]; then
  echo "[test_audit_deep_candidate_adjudicator_wiring] SKIP: tool missing at $TOOL"; exit 0
fi

PASS=0
FAIL=0
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

# ---------------------------------------------------------------------------
# Test 1 — Stage presence: functions defined AND called.
# ---------------------------------------------------------------------------
if grep -q 'run_deep_candidate_adjudicate()' "$TOOL" && \
   grep -q 'run_adversarial_candidate_verify()' "$TOOL"; then
  PASS=$((PASS+1)); echo "PASS: both adjudicator stage functions defined"
else
  FAIL=$((FAIL+1)); echo "FAIL: adjudicator stage function(s) not defined"
fi

# Both must be CALLED (not just defined) inside run_cross_lane_correlate.
if grep -E '^\s*run_deep_candidate_adjudicate "\$source_log"' "$TOOL" >/dev/null 2>&1 && \
   grep -E '^\s*run_adversarial_candidate_verify "\$source_log"' "$TOOL" >/dev/null 2>&1; then
  PASS=$((PASS+1)); echo "PASS: both adjudicator stages are called"
else
  FAIL=$((FAIL+1)); echo "FAIL: adjudicator stage(s) defined but not called"
fi

# ---------------------------------------------------------------------------
# Test 2 — Empty workspace: stages skip cleanly, rc=0.
# ---------------------------------------------------------------------------
WS1="$SANDBOX/empty"; mkdir -p "$WS1"
set +e
out1=$(timeout 180 bash "$TOOL" "$WS1" 2>&1); rc1=$?
set -e 2>/dev/null || true
REPORT1="$WS1/.audit_logs/audit_deep_report.md"
if [ "$rc1" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: empty-ws run exits 0"
else
  FAIL=$((FAIL+1)); echo "FAIL: empty-ws run rc=$rc1"
  echo "----- output tail -----"; echo "$out1" | tail -20; echo "-----------------------"
fi
if [ -f "$REPORT1" ] && \
   grep -q "Deep candidate adjudication (validate-deep-candidate)" "$REPORT1" && \
   grep -q "Adversarial candidate verification (3-lens refutation panel)" "$REPORT1"; then
  PASS=$((PASS+1)); echo "PASS: both adjudicator report sections present (empty ws)"
else
  FAIL=$((FAIL+1)); echo "FAIL: adjudicator report section(s) missing on empty ws"
fi
if [ -f "$REPORT1" ] && grep -q "SKIPPED no deep_candidates/\*.json to adjudicate" "$REPORT1"; then
  PASS=$((PASS+1)); echo "PASS: deep adjudication self-skips cleanly when no candidates"
else
  FAIL=$((FAIL+1)); echo "FAIL: deep adjudication did not self-skip cleanly"
fi

# ---------------------------------------------------------------------------
# Test 3 — Synthetic candidates: 1 valid + 1 invalid deep candidate, plus an
# exploit_queue with a critical + a low row.
# ---------------------------------------------------------------------------
WS3="$SANDBOX/with-candidates"; mkdir -p "$WS3/deep_candidates" "$WS3/.auditooor"

cat > "$WS3/deep_candidates/c1.json" <<'JSON'
{
  "schema_version": "deep_candidate.v1",
  "lane": "math",
  "candidate_id": "C-001",
  "files": ["src/Vault.sol"],
  "claim": "Reentrancy in withdraw drains funds. root cause at src/Vault.sol:42 reachable from external entrypoint; survives every defense layer to impact; negative control patched baseline prevents the drain.",
  "trigger": "call withdraw with malicious receiver",
  "impact": "theft of user funds",
  "reproduction": "forge test --match-test testReentrancy",
  "confidence": "medium",
  "blocking_questions": ["confirm guard absent at pin"],
  "promotion_status": "investigate"
}
JSON

# Invalid: reproduction placeholder + high confidence with rejected status.
cat > "$WS3/deep_candidates/c2.json" <<'JSON'
{
  "schema_version": "deep_candidate.v1",
  "lane": "math",
  "candidate_id": "C-002",
  "files": ["src/Other.sol"],
  "claim": "Some issue.",
  "trigger": "x",
  "impact": "y",
  "reproduction": "TBD",
  "confidence": "high",
  "blocking_questions": [],
  "promotion_status": "rejected"
}
JSON

cat > "$WS3/.auditooor/exploit_queue.json" <<'JSON'
{ "queue": [
  {"lead_id":"EQ-001","likely_severity":"critical","title":"reentrancy drain","root_cause_hypothesis":"missing guard","impact_probe":"theft"},
  {"lead_id":"EQ-002","likely_severity":"low","title":"cosmetic"}
]}
JSON

set +e
out3=$(timeout 180 bash "$TOOL" "$WS3" 2>&1); rc3=$?
set -e 2>/dev/null || true
if [ "$rc3" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: candidate-bearing run exits 0"
else
  FAIL=$((FAIL+1)); echo "FAIL: candidate-bearing run rc=$rc3"
  echo "----- output tail -----"; echo "$out3" | tail -20; echo "-----------------------"
fi

DEEP_JSON="$WS3/.audit_logs/deep_candidate_adjudication.json"
if [ -f "$DEEP_JSON" ] && python3 -c "
import json
d=json.load(open('$DEEP_JSON'))
assert d['schema_id']=='auditooor.deep_candidate_adjudication.v1', d
assert d['candidate_count']==2, d
assert d['kept']==1 and d['killed']==1, d
verdicts={r['candidate'].split('/')[-1]: r['verdict'] for r in d['results']}
assert verdicts.get('c1.json')=='kept', verdicts
assert verdicts.get('c2.json')=='killed', verdicts
print('deep-adjudication shape OK')
" 2>&1 | grep -q "shape OK"; then
  PASS=$((PASS+1)); echo "PASS: deep adjudication verdicted 2 candidates (1 kept, 1 killed)"
else
  FAIL=$((FAIL+1)); echo "FAIL: deep adjudication sidecar wrong/missing"
  [ -f "$DEEP_JSON" ] && python3 -c "import json;print(json.dumps(json.load(open('$DEEP_JSON')),indent=2))" 2>&1 | head -40
fi

ADV_JSON="$WS3/.audit_logs/adversarial_candidate_verify.json"
if [ -f "$ADV_JSON" ] && python3 -c "
import json
d=json.load(open('$ADV_JSON'))
assert d['schema_id']=='auditooor.adversarial_candidate_verify_batch.v1', d
# The critical exploit_queue row fires (Medium+); the low row is skipped.
ids={r['candidate'] for r in d['results']}
assert 'EQ-001' in ids, ('EQ-001 should be verdicted', ids)
assert 'EQ-002' not in ids, ('EQ-002 (low) should be skipped', ids)
eq1=[r for r in d['results'] if r['candidate']=='EQ-001'][0]
assert eq1['source']=='exploit_queue', eq1
assert eq1['panel_verdict'] in (
    'pass-survived-panel','pass-refutations-ruled-out','fail-killed-by-panel'), eq1
print('adversarial-panel shape OK')
" 2>&1 | grep -q "shape OK"; then
  PASS=$((PASS+1)); echo "PASS: adversarial panel verdicted the critical exploit_queue row, skipped low"
else
  FAIL=$((FAIL+1)); echo "FAIL: adversarial panel sidecar wrong/missing"
  [ -f "$ADV_JSON" ] && python3 -c "import json;print(json.dumps(json.load(open('$ADV_JSON')),indent=2))" 2>&1 | head -40
fi

# Hunter-handoff packet names the two new sidecars.
REPORT3="$WS3/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT3" ] && \
   grep -q "deep-candidate-adjudication-json:" "$REPORT3" && \
   grep -q "adversarial-candidate-verify-json:" "$REPORT3"; then
  PASS=$((PASS+1)); echo "PASS: Hunter Handoff names both adjudicator sidecars"
else
  FAIL=$((FAIL+1)); echo "FAIL: Hunter Handoff missing adjudicator sidecar pointer(s)"
fi

echo ""
echo "[test_audit_deep_candidate_adjudicator_wiring] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
