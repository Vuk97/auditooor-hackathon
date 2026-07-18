#!/usr/bin/env bash
# Focused audit-deep integration test for advisory Go/DLT scanners.
#
# Runs the default profile against a tiny Go workspace with no global
# AUDIT_DEEP_DRY_RUN so the scanners write their JSON artifacts. A sterile PATH
# exposes bash/coreutils and a python3 shim only, keeping optional deep-audit
# engines out of the test.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[test_audit_deep_go_dlt_wiring] SKIP: python3 not on PATH"
  exit 0
fi

FAIL=0
PASS=0
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

BIN="$SANDBOX/bin"
mkdir -p "$BIN"
ln -s "$(command -v python3)" "$BIN/python3"

WS="$SANDBOX/go-dlt-ws"
mkdir -p "$WS/wallet"
cat > "$WS/wallet/surfaces.go" <<'EOF'
package wallet

import "bytes"

var pendingTxids [][]byte

func trackTxid(txid []byte, blockTxids [][]byte) bool {
	if len(txid) != 32 {
		return false
	}
	pendingTxids = append(pendingTxids, txid)
	for _, blockTxid := range blockTxids {
		if bytes.Equal(txid, blockTxid) {
			return true
		}
	}
	return false
}

type StatechainWallet struct {
	VerifyingPubkey []byte `db:"verifying_pubkey"`
	RawRefundTx []byte `db:"raw_refund_tx"`
	SignedRefundTx []byte `db:"signed_refund_tx"`
}

type repo struct{}

func (repo) Put(id string, rawRefundTx []byte, signedRefundTx []byte) error { return nil }

var refundRepo repo

func TweakKeyShare(share []byte, tweak []byte) []byte {
	return append(share, tweak...)
}

func StoreRefund(id string, rawRefundTx []byte, signedRefundTx []byte) error {
	return refundRepo.Put(id, rawRefundTx, signedRefundTx)
}
EOF

python3 "$REPO/tools/audit-completion-marker.py" write --workspace "$WS" >/dev/null 2>&1

out="$(PATH="$BIN:/usr/bin:/bin:/usr/sbin:/sbin" bash "$REPO/tools/audit-deep.sh" "$WS" 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: audit-deep exits 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: audit-deep exit=$rc"
  echo "$out"
fi

REPORT="$WS/.audit_logs/audit_deep_report.md"
GATE_MANIFEST="$WS/.audit_logs/go_dlt_audit_enforcement.json"
TXID_JSON="$WS/.auditooor/go_txid_chain_truth_scan.json"
REFUND_JSON="$WS/.auditooor/go_refund_tweak_survivability_scan.json"

if [ -f "$REPORT" ] && grep -q "Go/DLT advisory scanners" "$REPORT" && \
   grep -q "audit prerequisite: PASS" "$REPORT" && \
   grep -q "NOT_SUBMIT_READY" "$REPORT" && \
   grep -q "go-dlt-advisory-scanners" "$REPORT" && \
   [ -f "$GATE_MANIFEST" ]; then
  PASS=$((PASS+1))
  echo "PASS: report includes Go/DLT audit gate and advisory step"
else
  FAIL=$((FAIL+1))
  echo "FAIL: report missing Go/DLT audit gate/advisory step"
  [ -f "$REPORT" ] && cat "$REPORT"
fi

if [ -f "$TXID_JSON" ] && [ -f "$REFUND_JSON" ]; then
  PASS=$((PASS+1))
  echo "PASS: Go/DLT scanner artifacts are written"
else
  FAIL=$((FAIL+1))
  echo "FAIL: missing Go/DLT scanner artifacts"
fi

json_check="$(python3 - "$TXID_JSON" "$REFUND_JSON" "$GATE_MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

txid = json.loads(Path(sys.argv[1]).read_text())
refund = json.loads(Path(sys.argv[2]).read_text())
gate = json.loads(Path(sys.argv[3]).read_text())

assert txid["advisory"] is True
assert txid["findings"], txid
assert txid["findings"][0]["submission_posture"] == "NOT_SUBMIT_READY"
assert txid["findings"][0]["advisory_only"] is True

assert refund["posture"] == "NOT_SUBMIT_READY"
assert refund["advisory_only"] is True
assert refund["submission_ready"] is False
assert refund["findings"], refund
assert refund["findings"][0]["posture"] == "NOT_SUBMIT_READY"

assert gate["schema"] == "auditooor.go_dlt_audit_enforcement.v1"
assert gate["status"] == "pass"
assert gate["audit_completion"]["exists"] is True
print("ok")
PY
)" || json_check=""

if [ "$json_check" = "ok" ]; then
  PASS=$((PASS+1))
  echo "PASS: scanner JSON stays advisory and gate manifest stays pass/fresh"
else
  FAIL=$((FAIL+1))
  echo "FAIL: scanner JSON / gate manifest check failed"
  [ -f "$TXID_JSON" ] && cat "$TXID_JSON"
  [ -f "$REFUND_JSON" ] && cat "$REFUND_JSON"
  [ -f "$GATE_MANIFEST" ] && cat "$GATE_MANIFEST"
fi

echo ""
echo "[test_audit_deep_go_dlt_wiring] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
