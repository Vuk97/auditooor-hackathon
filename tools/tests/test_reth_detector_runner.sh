#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="$ROOT/tools/reth-detector-runner.py"
AUDIT_DEEP="$ROOT/tools/audit-deep.sh"
PATTERNS="$ROOT/reference/patterns.dsl"
TMPDIR="${TMPDIR:-/tmp}/auditooor-reth-detector-test.$$"

pass=0
fail=0

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

_pass() {
  echo "PASS: $1"
  pass=$((pass + 1))
}

_fail() {
  echo "FAIL: $1"
  fail=$((fail + 1))
}

json_count() {
  python3 - "$1" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    print(data.get("summary", {}).get("findings_count", 0))
except Exception:
    print(0)
PY
}

run_case() {
  local name="$1"
  local workspace="$2"
  local pattern="$3"
  local expected="$4"
  local out="$TMPDIR/$name.json"

  python3 "$TOOL" "$ROOT/tests/fixtures/reth/$workspace" \
    --patterns-dir "$PATTERNS" --only "$pattern" --out "$out" --quiet
  rc=$?
  if [ "$rc" -ne 0 ]; then
    _fail "$name exits 0 (rc=$rc)"
    return
  fi
  got="$(json_count "$out")"
  if [ "$got" = "$expected" ]; then
    _pass "$name findings_count=$expected"
  else
    _fail "$name findings_count expected $expected got $got"
  fi
}

mkdir -p "$TMPDIR"

run_case "gas-limit-vuln" \
  "gas_limit_vuln" "reth-gas-limit-trie-disagreement" "1"
run_case "gas-limit-clean" \
  "gas_limit_clean" "reth-gas-limit-trie-disagreement" "0"
run_case "opcode-vuln" \
  "opcode_dispatch_vuln" "reth-opcode-dispatch-missing-cancun-prague" "1"
run_case "opcode-clean" \
  "opcode_dispatch_clean" "reth-opcode-dispatch-missing-cancun-prague" "0"
run_case "state-root-vuln" \
  "state_root_vuln" "reth-state-root-mismatch-on-empty-block" "1"
run_case "state-root-clean" \
  "state_root_clean" "reth-state-root-mismatch-on-empty-block" "0"
run_case "kona-blob-source-wraps-reset-as-temporary" \
  "r78" "kona-blob-source-wraps-reset-as-temporary" "1"
run_case "kona-executor-without-state-clear-post-spurious-dragon" \
  "r78" "kona-executor-without-state-clear-post-spurious-dragon" "1"
run_case "kona-trace-extension-trivial-dispute-win" \
  "r78" "kona-trace-extension-trivial-dispute-win" "1"
run_case "base-isthmus-withdrawals-root-parent-state-skip" \
  "r78" "base-isthmus-withdrawals-root-parent-state-skip" "1"
run_case "base-deposits-only-checks-option-wrapper" \
  "r78" "base-deposits-only-checks-option-wrapper" "1"
run_case "base-built-payload-drops-execution-requests" \
  "r78" "base-built-payload-drops-execution-requests" "1"
run_case "base-parent-beacon-root-defaults-before-new-payload" \
  "r78" "base-parent-beacon-root-defaults-before-new-payload" "1"

audit_ws="$TMPDIR/audit_ws"
cp -R "$ROOT/tests/fixtures/reth/state_root_vuln" "$audit_ws"
out="$(AUDIT_DEEP_DRY_RUN=1 bash "$AUDIT_DEEP" --dry-run "$audit_ws" 2>&1)"
report="$audit_ws/.audit_logs/audit_deep_report.md"
if [ -f "$report" ] && grep -q "reth-detector-runner.py" "$report"; then
  _pass "audit-deep dry-run includes reth detector command"
else
  _fail "audit-deep dry-run includes reth detector command"
fi

if [ -f "$report" ] && grep -q "Step 10" "$report"; then
  _pass "audit-deep report includes Step 10"
else
  _fail "audit-deep report includes Step 10"
fi

echo "RESULT: pass=$pass fail=$fail"
if [ "$fail" -ne 0 ]; then
  exit 1
fi
exit 0
