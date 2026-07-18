#!/usr/bin/env bash
# test_audit_deep_target.sh — regression test for `make audit-deep` and the
# tools/audit-deep.sh aggregator (v3 Slice 4).
#
# Assertions:
#   1. tools/audit-deep.sh --dry-run against a sandboxed workspace exits 0,
#      with NO halmos / medusa / etc actually invoked (DRY_RUN path).
#   2. The report file <ws>/.audit_logs/audit_deep_report.md is created.
#   3. The report contains the tool-availability table (every documented
#      tool listed with ✓ or ✗).
#   4. The report contains a "Summary" section with `ran:` and `skipped:` lines.
#   5. Even when no optional tool is on PATH (we strip them from PATH),
#      the script still exits 0 — confirms the graceful-skip contract.
#   6. docs/TOOL_COST_BENEFIT.md exists and has the matrix headers the v3
#      Slice 4 spec requires.
#   7. Makefile exposes `audit-deep` and `audit-deep-test` targets.
#   8. Bad workspace argument exits non-zero (argument-validation still
#      tight even though tool-skip is permissive).
#
# Skips cleanly if bash/make/python3 are unavailable. No network.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if ! command -v bash >/dev/null 2>&1; then
  echo "[test_audit_deep_target] SKIP: bash not on PATH"
  exit 0
fi
if ! command -v make >/dev/null 2>&1; then
  echo "[test_audit_deep_target] SKIP: make not on PATH"
  exit 0
fi

FAIL=0
PASS=0

write_fresh_audit_marker() {
  local ws="$1"
  python3 "$REPO/tools/audit-completion-marker.py" write --workspace "$ws" >/dev/null 2>&1
}

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
WS="$SANDBOX/audits/deep-test"
mkdir -p "$WS"

# --- 1 + 2 + 3 + 4: dry-run smoke against sandboxed workspace ---------------
out="$(AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS" 2>&1)"
rc=$?

if [ "$rc" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: dry-run exit 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: dry-run exit=$rc"
  echo "----- stdout/stderr -----"
  echo "$out"
  echo "-------------------------"
fi

REPORT="$WS/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT" ]; then
  PASS=$((PASS+1))
  echo "PASS: report file created at $REPORT"
else
  FAIL=$((FAIL+1))
  echo "FAIL: report file missing at $REPORT"
fi

if [ -f "$REPORT" ]; then
  for tool in forge halmos medusa echidna mythril slither; do
    if grep -qE "^\| $tool \|" "$REPORT"; then
      PASS=$((PASS+1))
      echo "PASS: report lists tool '$tool' in availability table"
    else
      FAIL=$((FAIL+1))
      echo "FAIL: report missing tool '$tool' row"
    fi
  done
  if grep -q "^## Summary" "$REPORT"; then
    PASS=$((PASS+1))
    echo "PASS: report has Summary section"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: report missing Summary section"
  fi
  if grep -q "^- ran:" "$REPORT" && grep -q "^- skipped:" "$REPORT"; then
    PASS=$((PASS+1))
    echo "PASS: report has ran/skipped lines"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: report missing ran/skipped lines"
  fi
  if grep -q "^## Deep counterexample collection" "$REPORT" && \
     grep -q "^## Deep counterexample execution queue" "$REPORT" && \
     grep -q "queue rows are model-routed work items, not proof" "$REPORT" && \
     [ -f "$WS/deep_counterexamples/collection_manifest.json" ] && \
     [ -f "$WS/deep_counterexamples/execution_queue.json" ] && \
     [ -f "$WS/deep_counterexamples/execution_queue.md" ]; then
    PASS=$((PASS+1))
    echo "PASS: default profile auto-collects and queues deep counterexample work"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: default profile missing deep counterexample collection/queue section or artifact"
  fi
fi

# --- 5: hostile PATH (no halmos / medusa / etc) still exits 0 ---------------
# We can't easily strip /usr/bin (need bash, mkdir, etc). Instead we point
# the script at a workspace and a curated PATH that excludes the optional
# tools — rely on `command -v` to return non-zero for them. The host may or
# may not have these installed; the test asserts exit 0 regardless.
WS2="$SANDBOX/audits/deep-test-2"
mkdir -p "$WS2"

# Sterile PATH: only stdlib utility dirs. Exclude common foundryup / python
# venv dirs where halmos/medusa/echidna might live.
STERILE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

out2="$(PATH="$STERILE_PATH" AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS2" 2>&1)"
rc2=$?

if [ "$rc2" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: hostile PATH (no optional tools) — script still exits 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: hostile PATH — exit $rc2 (graceful-skip contract violated)"
  echo "----- output -----"
  echo "$out2"
  echo "------------------"
fi

REPORT2="$WS2/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT2" ] && grep -q "not installed" "$REPORT2"; then
  PASS=$((PASS+1))
  echo "PASS: hostile PATH — report mentions 'not installed' for missing tools"
else
  FAIL=$((FAIL+1))
  echo "FAIL: hostile PATH — report missing 'not installed' note"
fi

# --- 5a: existing MCP memory receipt is surfaced in audit-deep report -------
WS_RECEIPT="$SANDBOX/audits/deep-test-receipt"
mkdir -p "$WS_RECEIPT/.auditooor/memory_context_packs"
cat > "$WS_RECEIPT/.auditooor/memory_context_receipt.json" <<EOF
{
  "schema": "auditooor.memory_context_receipt.v1",
  "workspace": "deep-test-receipt",
  "workspace_path": "$WS_RECEIPT",
  "generated_at": "2026-05-12T00:00:00Z",
  "loaded_contexts": [
    {
      "requirement_id": "dispatch-context",
      "context_kind": "dispatch",
      "tool": "vault_dispatch_context",
      "context_pack_id": "auditooor.vault_context_pack.v1:dispatch:abcdef0123456789",
      "context_pack_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "pack_path": "$WS_RECEIPT/.auditooor/memory_context_packs/dispatch.json",
      "loaded_at": "2026-05-12T00:00:01Z",
      "status": "loaded"
    }
  ],
  "summary": {
    "required_count": 1,
    "loaded_count": 1,
    "missing_count": 0,
    "stale_count": 0,
    "strict_ready": true
  }
}
EOF

out_receipt="$(AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS_RECEIPT" 2>&1)"
rc_receipt=$?
REPORT_RECEIPT="$WS_RECEIPT/.audit_logs/audit_deep_report.md"
if [ "$rc_receipt" -eq 0 ] && [ -f "$REPORT_RECEIPT" ] && \
   grep -q "^## MCP Memory Context Receipt" "$REPORT_RECEIPT" && \
   grep -q "memory_context_receipt.json" "$REPORT_RECEIPT" && \
   grep -q "auditooor.vault_context_pack.v1:dispatch:abcdef0123456789" "$REPORT_RECEIPT" && \
   grep -q "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" "$REPORT_RECEIPT"; then
  PASS=$((PASS+1))
  echo "PASS: audit-deep surfaces existing MCP memory receipt evidence"
else
  FAIL=$((FAIL+1))
  echo "FAIL: audit-deep did not surface existing MCP memory receipt evidence"
  echo "----- output -----"
  echo "$out_receipt"
  echo "----- report -----"
  [ -f "$REPORT_RECEIPT" ] && cat "$REPORT_RECEIPT"
  echo "------------------"
fi

# --- 5b: Rust DLT nested under external/<project> still triggers graphs ----
WS_RUST="$SANDBOX/audits/deep-rust-external"
mkdir -p "$WS_RUST/external/base/crates/execution/payload/src" \
         "$WS_RUST/external/base/crates/consensus/derive/src"
cat > "$WS_RUST/external/base/Cargo.toml" <<'EOF'
[workspace]
members = ["crates/*/*"]
EOF
cat > "$WS_RUST/external/base/crates/execution/payload/Cargo.toml" <<'EOF'
[package]
name = "base-execution-payload"
EOF
cat > "$WS_RUST/external/base/crates/execution/payload/src/lib.rs" <<'EOF'
pub fn payload_entry() {}
EOF
cat > "$WS_RUST/external/base/crates/consensus/derive/Cargo.toml" <<'EOF'
[package]
name = "base-consensus-derive"
EOF
cat > "$WS_RUST/external/base/crates/consensus/derive/src/lib.rs" <<'EOF'
pub fn derive_entry() {}
EOF

out_rust="$(AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS_RUST" 2>&1)"
rc_rust=$?
REPORT_RUST="$WS_RUST/.audit_logs/audit_deep_report.md"
if [ "$rc_rust" -eq 0 ] && [ -f "$REPORT_RUST" ] && \
   grep -q "rust-source-graph" "$REPORT_RUST" && \
   grep -q "rust-cross-crate-graph" "$REPORT_RUST" && \
   grep -q "planned:.*rust-source-graph.py" "$REPORT_RUST" && \
   grep -q "planned:.*rust-cross-crate-graph.py" "$REPORT_RUST"; then
  PASS=$((PASS+1))
  echo "PASS: nested external Rust checkout triggers source + cross-crate graph steps"
else
  FAIL=$((FAIL+1))
  echo "FAIL: nested external Rust checkout did not trigger Rust graph steps"
  echo "----- output -----"
  echo "$out_rust"
  echo "----- report -----"
  [ -f "$REPORT_RUST" ] && cat "$REPORT_RUST"
  echo "------------------"
fi

# --- 5c: Go/DLT advisory scanners are wired into audit-deep dry-run ---------
WS_GO="$SANDBOX/audits/deep-go-dlt"
mkdir -p "$WS_GO/wallet"
cat > "$WS_GO/wallet/txid.go" <<'EOF'
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
EOF

if command -v python3 >/dev/null 2>&1; then
  write_fresh_audit_marker "$WS_GO"

  out_go="$(AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS_GO" 2>&1)"
  rc_go=$?
  REPORT_GO="$WS_GO/.audit_logs/audit_deep_report.md"
  GO_GATE_MANIFEST="$WS_GO/.audit_logs/go_dlt_audit_enforcement.json"
  if [ "$rc_go" -eq 0 ] && [ -f "$REPORT_GO" ] && [ -f "$GO_GATE_MANIFEST" ] && \
     grep -q "Go/DLT advisory scanners" "$REPORT_GO" && \
     grep -q "audit prerequisite: PASS" "$REPORT_GO" && \
     grep -q "planned:.*go-txid-chain-truth-scan.py" "$REPORT_GO" && \
     grep -q "planned:.*go-refund-tweak-survivability-scan.py" "$REPORT_GO" && \
     grep -q "submission_posture=NOT_SUBMIT_READY" "$REPORT_GO" && \
     grep -q "go_txid_chain_truth_scan.json" "$REPORT_GO" && \
     grep -q "go_refund_tweak_survivability_scan.json" "$REPORT_GO" && \
     grep -q '"status": "pass"' "$GO_GATE_MANIFEST"; then
    PASS=$((PASS+1))
    echo "PASS: Go/DLT dry-run wiring requires fresh audit evidence and writes a pass manifest"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: Go/DLT advisory scanner dry-run wiring missing"
    echo "----- output -----"
    echo "$out_go"
    echo "----- report -----"
    [ -f "$REPORT_GO" ] && cat "$REPORT_GO"
    echo "----- manifest -----"
    [ -f "$GO_GATE_MANIFEST" ] && cat "$GO_GATE_MANIFEST"
    echo "------------------"
  fi

  # --- 5d: Go/DLT audit-deep fails closed without fresh make-audit evidence ---
  WS_GO_BLOCKED="$SANDBOX/audits/deep-go-dlt-missing-marker"
  mkdir -p "$WS_GO_BLOCKED/wallet"
  cp "$WS_GO/wallet/txid.go" "$WS_GO_BLOCKED/wallet/txid.go"

  out_go_blocked="$(AUDIT_DEEP_DRY_RUN=1 bash "$REPO/tools/audit-deep.sh" --dry-run "$WS_GO_BLOCKED" 2>&1)"
  rc_go_blocked=$?
  REPORT_GO_BLOCKED="$WS_GO_BLOCKED/.audit_logs/audit_deep_report.md"
  GO_GATE_BLOCKED="$WS_GO_BLOCKED/.audit_logs/go_dlt_audit_enforcement.json"
  if [ "$rc_go_blocked" -ne 0 ] && [ -f "$REPORT_GO_BLOCKED" ] && [ -f "$GO_GATE_BLOCKED" ] && \
     grep -q "audit prerequisite: FAIL" "$REPORT_GO_BLOCKED" && \
     grep -q "blocked until canonical audit evidence exists" "$REPORT_GO_BLOCKED" && \
     grep -q '"status": "fail"' "$GO_GATE_BLOCKED"; then
    PASS=$((PASS+1))
    echo "PASS: Go/DLT audit-deep fails closed without fresh make-audit evidence"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: Go/DLT audit enforcement did not fail closed without marker"
    echo "----- output -----"
    echo "$out_go_blocked"
    echo "----- report -----"
    [ -f "$REPORT_GO_BLOCKED" ] && cat "$REPORT_GO_BLOCKED"
    echo "----- manifest -----"
    [ -f "$GO_GATE_BLOCKED" ] && cat "$GO_GATE_BLOCKED"
    echo "--------------------"
  fi
else
  echo "SKIP: Go/DLT audit enforcement subtests require python3"
fi

# --- 6: docs/TOOL_COST_BENEFIT.md sanity ------------------------------------
DOC="$REPO/docs/TOOL_COST_BENEFIT.md"
if [ -f "$DOC" ]; then
  PASS=$((PASS+1))
  echo "PASS: docs/TOOL_COST_BENEFIT.md exists"
else
  FAIL=$((FAIL+1))
  echo "FAIL: docs/TOOL_COST_BENEFIT.md missing"
fi

if [ -f "$DOC" ]; then
  # The v3 Slice 4 spec mandates a tool inventory and a per-engagement
  # decision matrix. Confirm both shapes are present.
  for needle in \
    "## TL;DR — decision matrix per engagement type" \
    "## Tool inventory" \
    "### Halmos" \
    "### Medusa" \
    "### Hydra" \
    "### Slither" \
    "### Foundry"
  do
    if grep -q "$needle" "$DOC"; then
      PASS=$((PASS+1))
      echo "PASS: doc has section '$needle'"
    else
      FAIL=$((FAIL+1))
      echo "FAIL: doc missing section '$needle'"
    fi
  done
fi

# --- 7: Makefile exposes the targets ----------------------------------------
if grep -qE "^audit-deep:" "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Makefile has audit-deep target"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Makefile missing audit-deep target"
fi
if grep -qE "^audit-deep-test:" "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Makefile has audit-deep-test target"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Makefile missing audit-deep-test target"
fi
if grep -qE "^audit-deep-medium:" "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Makefile has audit-deep-medium target"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Makefile missing audit-deep-medium target"
fi
# .PHONY registration
if grep -qE "^\.PHONY:.*audit-deep( |$)" "$REPO/Makefile" || \
   grep -qE "^\.PHONY:.*audit-deep " "$REPO/Makefile"; then
  PASS=$((PASS+1))
  echo "PASS: Makefile .PHONY includes audit-deep"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Makefile .PHONY missing audit-deep"
fi

# --- 7a: medium profile dry-run smoke --------------------------------------
WS_MEDIUM="$SANDBOX/audits/deep-test-medium"
mkdir -p "$WS_MEDIUM"
out_medium="$(AUDIT_DEEP_DRY_RUN=1 SKIP_REGEX=1 bash "$REPO/tools/audit-deep.sh" --dry-run --profile medium "$WS_MEDIUM" 2>&1)"
rc_medium=$?
REPORT_MEDIUM="$WS_MEDIUM/.audit_logs/audit_deep_report.md"
if [ "$rc_medium" -eq 0 ] && [ -f "$REPORT_MEDIUM" ] && \
   grep -q "profile: medium" "$REPORT_MEDIUM" && \
   grep -q "medium bounds:" "$REPORT_MEDIUM" && \
   ls "$WS_MEDIUM/.audit_logs"/audit_deep_medium_*.md >/dev/null 2>&1; then
  PASS=$((PASS+1))
  echo "PASS: --profile medium dry-run exits 0 and writes medium report"
else
  FAIL=$((FAIL+1))
  echo "FAIL: --profile medium dry-run failed or missing report"
  echo "----- output -----"
  echo "$out_medium"
  echo "------------------"
fi

# Strict V3 closeout tail is advisory for proof conversion by default. Hard
# enforcement belongs to ENFORCE_AUTONOMOUS_PROOF_CONVERSION, not STRICT alone.
strict_out="$(cd "$REPO" && AUDIT_DEEP_SKIP_AUDIT_PREREQ=1 make -n audit-deep WS="$WS" STRICT=1 2>&1)"
strict_missing=0
for needle in \
  'prove-top-leads WS="$ws" TOP_N="10" STRICT=1 JSON=1 || \' \
  'exploit-conversion-loop WS="$ws" TOP_N="10" STRICT=1 JSON=1 > "$ws/.auditooor/exploit_conversion_loop_audit_deep.json" || \' \
  'queue-proof-hard-close WS="$ws" STRICT=1 || \' \
  'field-validation-report WS="$ws" STRICT=1 || \' \
  'v3-roadmap-sidecars WS="$ws" STRICT_HACKERMAN_V3=1 || \'
do
  if ! echo "$strict_out" | grep -qF -- "$needle"; then
    strict_missing=$((strict_missing+1))
    echo "FAIL: strict audit-deep dry-run missing expected advisory/closeout command: $needle"
  fi
done
if [ "$strict_missing" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: audit-deep STRICT=1 V3 tail matches advisory proof-conversion behavior"
else
  FAIL=$((FAIL+strict_missing))
  echo "----- strict audit-deep dry-run output -----"
  echo "$strict_out"
  echo "--------------------------------------------"
fi

# --- 8: bad workspace argument fails ----------------------------------------
out_bad="$(bash "$REPO/tools/audit-deep.sh" --dry-run /this/path/does/not/exist 2>&1)"
rc_bad=$?
if [ "$rc_bad" -ne 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: bad workspace path — script exits non-zero (got $rc_bad)"
else
  FAIL=$((FAIL+1))
  echo "FAIL: bad workspace path — expected non-zero exit, got 0"
  echo "----- output -----"
  echo "$out_bad"
  echo "------------------"
fi

# Missing workspace argument also fails.
out_none="$(bash "$REPO/tools/audit-deep.sh" --dry-run 2>&1)"
rc_none=$?
if [ "$rc_none" -ne 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: no workspace arg — script exits non-zero (got $rc_none)"
else
  FAIL=$((FAIL+1))
  echo "FAIL: no workspace arg — expected non-zero exit, got 0"
fi

# --- 9: all-profile handoff manifest ----------------------------------------
WS3="$SANDBOX/audits/deep-test-all"
mkdir -p "$WS3"
out_all="$(AUDIT_DEEP_DRY_RUN=1 AUDIT_DEEP_ALL_MAX_SECONDS=999 AUDITOOOR_AUDIT_RUN_FULL_ID=auditrun-shell-all bash "$REPO/tools/audit-deep.sh" --profile all "$WS3" 2>&1)"
rc_all=$?
if [ "$rc_all" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: --profile all dry-run exits 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: --profile all dry-run exit=$rc_all"
  echo "----- output -----"
  echo "$out_all"
  echo "------------------"
fi

ALL_REPORT="$WS3/.audit_logs/audit_deep_all_report.md"
ALL_MANIFEST="$WS3/.audit_logs/audit_deep_all_manifest.json"
ALL_PROMOTIONS="$WS3/.audit_logs/typed_candidate_promotions.json"
ALL_COLLECTION="$WS3/deep_counterexamples/collection_manifest.json"
ALL_QUEUE="$WS3/deep_counterexamples/execution_queue.json"
ALL_QUEUE_MD="$WS3/deep_counterexamples/execution_queue.md"
if [ -f "$ALL_REPORT" ] && [ -f "$ALL_MANIFEST" ] && [ -f "$ALL_PROMOTIONS" ] && [ -f "$ALL_COLLECTION" ] && [ -f "$ALL_QUEUE" ] && [ -f "$ALL_QUEUE_MD" ]; then
  PASS=$((PASS+1))
  echo "PASS: --profile all writes report + manifest + typed promotion + deep counterexample collection/queue"
else
  FAIL=$((FAIL+1))
  echo "FAIL: --profile all missing report, manifest, typed promotion, deep collection, or queue"
fi

if [ -f "$ALL_MANIFEST" ] && grep -q '"schema": "auditooor.audit_deep_all.v1"' "$ALL_MANIFEST" && \
   grep -q '"profile": "default"' "$ALL_MANIFEST" && \
   grep -q '"profile": "math"' "$ALL_MANIFEST" && \
   grep -q '"profile": "econ"' "$ALL_MANIFEST" && \
   grep -q '"profile": "crypto"' "$ALL_MANIFEST" && \
   grep -q '"run_id": "auditrun-shell-all"' "$ALL_MANIFEST" && \
   grep -q '"expected_profiles":' "$ALL_MANIFEST" && \
   grep -q '"typed_candidate_promotion"' "$ALL_MANIFEST" && \
   grep -q '"deep_counterexample_collection"' "$ALL_MANIFEST" && \
   grep -q '"deep_counterexample_queue"' "$ALL_MANIFEST" && \
   grep -q 'UNSAFE_TO_SUBMIT' "$ALL_MANIFEST"; then
  PASS=$((PASS+1))
  echo "PASS: --profile all manifest contains child profiles + promotion/collection/queue pointers + LLM guardrail"
else
  FAIL=$((FAIL+1))
  echo "FAIL: --profile all manifest missing expected profile/collection/queue/guardrail content"
fi

WS4="$SANDBOX/audits/deep-test-all-budget"
mkdir -p "$WS4"
out_budget="$(AUDIT_DEEP_DRY_RUN=1 AUDIT_DEEP_ALL_MAX_SECONDS=0 AUDIT_DEEP_ALL_PROFILES='default' bash "$REPO/tools/audit-deep.sh" --profile all "$WS4" 2>&1)"
rc_budget=$?
if [ "$rc_budget" -eq 0 ] && [ -f "$WS4/.audit_logs/audit_deep_all_manifest.json" ]; then
  PASS=$((PASS+1))
  echo "PASS: --profile all accepts budget env + custom child profile list"
else
  FAIL=$((FAIL+1))
  echo "FAIL: --profile all budget/custom-profile smoke failed"
  echo "----- output -----"
  echo "$out_budget"
  echo "------------------"
fi

echo ""
echo "[test_audit_deep_target] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
