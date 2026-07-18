#!/usr/bin/env bash
# test_audit_deep_invariant_ledger_wiring.sh — PR #511 Slice 5 wiring test.
#
# Asserts that tools/audit-deep.sh:
#   1. Self-skips cleanly when no invariant ledger is present (default WARN,
#      exit 0). Step 0b log line names the missing path AND the remediation.
#   2. Promotes that missing-ledger WARN to a FAIL (exit != 0) under
#      REQUIRE_INVARIANT_LEDGER=1.
#   3. Runs Step 12 cleanly against a synthetic ledger of 3 valid rows and
#      writes both deep-summary artifacts plus the Slice 2 manifest.
#   4. WARNs but exits 0 when a High row lacks a runnable harness/replay/
#      blocker; FAILs (exit != 0) under REQUIRE_HIGH_IMPACT_INVARIANTS=1.
#   5. Is idempotent — re-running against an unchanged ledger leaves the
#      content of the manifest unchanged (timestamps excepted).
#   6. Pointers section emits the deep summary path.
#
# stdlib-only. Skips gracefully if bash/python3 are missing.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TOOL="$REPO/tools/audit-deep.sh"

if ! command -v bash >/dev/null 2>&1; then
  echo "[test_audit_deep_invariant_ledger_wiring] SKIP: bash missing"; exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[test_audit_deep_invariant_ledger_wiring] SKIP: python3 missing"; exit 0
fi
if [ ! -f "$TOOL" ]; then
  echo "[test_audit_deep_invariant_ledger_wiring] SKIP: tool missing at $TOOL"; exit 0
fi

PASS=0
FAIL=0
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

run() { # run <label> <expect-rc> <ws> [env...]
  local label="$1" expect="$2" ws="$3"; shift 3
  local out rc
  set +e
  # shellcheck disable=SC2068
  out=$(env $@ AUDIT_DEEP_DRY_RUN=1 bash "$TOOL" --dry-run "$ws" 2>&1)
  rc=$?
  set -e 2>/dev/null || true
  if [ "$expect" = "nonzero" ]; then
    if [ "$rc" -ne 0 ]; then
      PASS=$((PASS+1)); echo "PASS: $label (rc=$rc)"
    else
      FAIL=$((FAIL+1)); echo "FAIL: $label expected nonzero rc, got 0"
      echo "----- output -----"; echo "$out"; echo "------------------"
    fi
  else
    if [ "$rc" -eq "$expect" ]; then
      PASS=$((PASS+1)); echo "PASS: $label (rc=$rc)"
    else
      FAIL=$((FAIL+1)); echo "FAIL: $label expected rc=$expect, got rc=$rc"
      echo "----- output -----"; echo "$out"; echo "------------------"
    fi
  fi
  printf '%s' "$out" > "$ws/.last_audit_deep.out"
}

# ---------------------------------------------------------------------------
# Test 1 — Empty workspace, no ledger. WARN exits 0.
# ---------------------------------------------------------------------------
WS1="$SANDBOX/empty"; mkdir -p "$WS1"
run "empty-ws default WARN exits 0" 0 "$WS1"
REPORT1="$WS1/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT1" ] && grep -q "Step 0b — Invariant ledger presence" "$REPORT1" && \
   grep -q "no invariant ledger present" "$REPORT1" && \
   grep -q "make invariant-ledger WS=" "$REPORT1"; then
  PASS=$((PASS+1)); echo "PASS: Step 0b WARN log line names path + remediation"
else
  FAIL=$((FAIL+1)); echo "FAIL: Step 0b WARN log missing remediation"
fi
if [ -f "$REPORT1" ] && grep -q "Step 12 — Invariant ledger summary" "$REPORT1"; then
  PASS=$((PASS+1)); echo "PASS: Step 12 header present even when ledger absent (self-skip)"
else
  FAIL=$((FAIL+1)); echo "FAIL: Step 12 header missing under self-skip path"
fi

# ---------------------------------------------------------------------------
# Test 2 — Empty workspace, REQUIRE_INVARIANT_LEDGER=1 fails.
# ---------------------------------------------------------------------------
WS2="$SANDBOX/empty-strict"; mkdir -p "$WS2"
run "REQUIRE_INVARIANT_LEDGER=1 fails" nonzero "$WS2" REQUIRE_INVARIANT_LEDGER=1
REPORT2="$WS2/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT2" ] && grep -q "REQUIRE_INVARIANT_LEDGER=1" "$REPORT2"; then
  PASS=$((PASS+1)); echo "PASS: strict-mode log mentions REQUIRE_INVARIANT_LEDGER=1"
else
  FAIL=$((FAIL+1)); echo "FAIL: strict-mode log missing env-var verbiage"
fi

# ---------------------------------------------------------------------------
# Test 3 — Synthetic ledger with 3 valid rows. Live (DRY_RUN=0) Step 12 path.
# ---------------------------------------------------------------------------
WS3="$SANDBOX/with-ledger"; mkdir -p "$WS3/.auditooor"
cat > "$WS3/.auditooor/invariant_ledger.json" <<'JSON'
{
  "schema": "auditooor.invariant_ledger.v1",
  "rows": [
    {"id":"X-I01","scope_asset":"X","invariant_family":"f","statement":"s","status":"executed_clean","required_engine":"forge","owner":"Claude","artifacts":[],"source_citations":["SCOPE.md::X"],"harness_target":"test/X.t.sol"},
    {"id":"X-I02","scope_asset":"Y","invariant_family":"f","statement":"s","status":"scaffolded","required_engine":"cargo","owner":"Claude","artifacts":[],"source_citations":["SCOPE.md::Y"],"harness_target":"crates/y/tests/y.rs"},
    {"id":"X-I03","scope_asset":"Z","invariant_family":"f","statement":"s","status":"blocked","required_engine":"manual","owner":"Claude","artifacts":["blocker: missing-rpc"],"source_citations":["SCOPE.md::Z"],"harness_target":""}
  ]
}
JSON

set +e
out3=$(bash "$TOOL" "$WS3" 2>&1); rc3=$?
set -e 2>/dev/null || true
if [ "$rc3" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: synthetic 3-row ledger live run exits 0"
else
  FAIL=$((FAIL+1)); echo "FAIL: synthetic 3-row ledger run rc=$rc3"
  echo "----- output -----"; echo "$out3"; echo "------------------"
fi

DEEP_JSON="$WS3/.audit_logs/invariant_ledger_deep_summary.json"
DEEP_MD="$WS3/.audit_logs/invariant_ledger_deep_summary.md"
MANIFEST="$WS3/.audit_logs/invariant_ledger_manifest.json"
for art in "$DEEP_JSON" "$DEEP_MD" "$MANIFEST"; do
  if [ -f "$art" ]; then
    PASS=$((PASS+1)); echo "PASS: artifact written -> $(basename "$art")"
  else
    FAIL=$((FAIL+1)); echo "FAIL: missing artifact $art"
  fi
done

# Pointers section names the deep summary path.
REPORT3="$WS3/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT3" ] && grep -q "invariant ledger summary:" "$REPORT3" && \
   grep -q "invariant_ledger_deep_summary.md" "$REPORT3" && \
   grep -q "invariant ledger manifest:" "$REPORT3"; then
  PASS=$((PASS+1)); echo "PASS: Pointers section names deep summary + manifest"
else
  FAIL=$((FAIL+1)); echo "FAIL: Pointers section missing invariant ledger lines"
fi

# Deep summary content sanity.
if [ -f "$DEEP_JSON" ] && python3 -c "
import json,sys
d=json.load(open('$DEEP_JSON'))
assert d['schema']=='auditooor.invariant_ledger_deep_summary.v1', d
assert d['row_count']==3, d
sc=d['status_counts']
assert sc.get('executed_clean')==1 and sc.get('scaffolded')==1 and sc.get('blocked')==1, sc
hq=d['harness_queue']
assert len(hq)==2, hq
print('deep-json shape OK')
" 2>&1 | grep -q "shape OK"; then
  PASS=$((PASS+1)); echo "PASS: deep summary JSON has expected shape"
else
  FAIL=$((FAIL+1)); echo "FAIL: deep summary JSON shape wrong"
  python3 -c "import json;print(json.dumps(json.load(open('$DEEP_JSON')),indent=2))" 2>&1 | head -30
fi

# ---------------------------------------------------------------------------
# Test 4 — High row missing harness. WARN default, FAIL strict.
# ---------------------------------------------------------------------------
WS4="$SANDBOX/high-missed"; mkdir -p "$WS4/.auditooor"
cat > "$WS4/.auditooor/invariant_ledger.json" <<'JSON'
{
  "schema": "auditooor.invariant_ledger.v1",
  "rows": [
    {"id":"H-I01","scope_asset":"H","invariant_family":"f","statement":"s","status":"missing_harness","required_engine":"forge","owner":"Claude","artifacts":[],"source_citations":["SCOPE.md::H"],"severity":"High"}
  ]
}
JSON

set +e
out4=$(bash "$TOOL" "$WS4" 2>&1); rc4=$?
set -e 2>/dev/null || true
if [ "$rc4" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: High-row missing harness — default WARN exits 0"
else
  FAIL=$((FAIL+1)); echo "FAIL: High-row default expected rc=0, got $rc4"
fi

WS4B="$SANDBOX/high-missed-strict"; mkdir -p "$WS4B/.auditooor"
cp "$WS4/.auditooor/invariant_ledger.json" "$WS4B/.auditooor/"
set +e
out4b=$(REQUIRE_HIGH_IMPACT_INVARIANTS=1 bash "$TOOL" "$WS4B" 2>&1); rc4b=$?
set -e 2>/dev/null || true
if [ "$rc4b" -ne 0 ]; then
  PASS=$((PASS+1)); echo "PASS: REQUIRE_HIGH_IMPACT_INVARIANTS=1 fails on High row missing harness (rc=$rc4b)"
else
  FAIL=$((FAIL+1)); echo "FAIL: REQUIRE_HIGH_IMPACT_INVARIANTS=1 expected nonzero, got 0"
  echo "----- output -----"; echo "$out4b"; echo "------------------"
fi

REPORT4B="$WS4B/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT4B" ] && grep -q "REQUIRE_HIGH_IMPACT_INVARIANTS=1" "$REPORT4B"; then
  PASS=$((PASS+1)); echo "PASS: strict-mode high-impact log mentions env-var verbiage"
else
  FAIL=$((FAIL+1)); echo "FAIL: high-impact strict log missing env-var verbiage"
fi

# ---------------------------------------------------------------------------
# Test 4b — Recon/Chimera bridge logs advisory scaffold plan when scaffold
# mode is enabled. DRY_RUN writes the manifest but no harness directory.
# ---------------------------------------------------------------------------
WS4C="$SANDBOX/chimera-ledger"; mkdir -p "$WS4C/.auditooor" "$WS4C/src"
cat > "$WS4C/src/Vault.sol" <<'EOF'
contract Vault { function withdraw() external {} }
EOF
cat > "$WS4C/.auditooor/invariant_ledger.json" <<'JSON'
{
  "schema": "auditooor.invariant_ledger.v1",
  "rows": [
    {"id":"SOL-I01","scope_asset":"Vault","invariant_family":"f","statement":"s","status":"scaffolded","required_engine":"forge","owner":"Claude","artifacts":[],"source_citations":["src/Vault.sol:1"],"harness_target":"test/VaultInvariant.t.sol"}
  ]
}
JSON

run "AUDIT_DEEP_SCAFFOLD=1 plans Chimera ledger scaffold" 0 "$WS4C" AUDIT_DEEP_SCAFFOLD=1
CHIMERA_MANIFEST="$WS4C/.audit_logs/chimera_scaffold_manifest.json"
if [ -f "$CHIMERA_MANIFEST" ] && python3 -c "
import json
d=json.load(open('$CHIMERA_MANIFEST'))
assert d['schema']=='auditooor.chimera_ledger_scaffold.v1', d
assert d['dry_run'] is True, d
assert d['status_counts'].get('planned') == 1, d
print('chimera manifest OK')
" 2>&1 | grep -q "chimera manifest OK"; then
  PASS=$((PASS+1)); echo "PASS: Chimera ledger scaffold manifest written in dry-run mode"
else
  FAIL=$((FAIL+1)); echo "FAIL: Chimera ledger scaffold manifest missing/wrong"
  [ -f "$CHIMERA_MANIFEST" ] && cat "$CHIMERA_MANIFEST"
fi
if [ ! -d "$WS4C/chimera_harnesses/SOL-I01" ]; then
  PASS=$((PASS+1)); echo "PASS: Chimera dry-run did not create harness directory"
else
  FAIL=$((FAIL+1)); echo "FAIL: Chimera dry-run unexpectedly created harness directory"
fi

# ---------------------------------------------------------------------------
# Test 5 — Idempotency: re-run against unchanged ledger leaves manifest
# content stable (timestamps excepted).
# ---------------------------------------------------------------------------
WS5="$SANDBOX/idem"; mkdir -p "$WS5/.auditooor"
cp "$WS3/.auditooor/invariant_ledger.json" "$WS5/.auditooor/"

set +e
bash "$TOOL" "$WS5" >/dev/null 2>&1
rc5a=$?
MAN5="$WS5/.audit_logs/invariant_ledger_manifest.json"
HASH_A=$(python3 -c "
import json
d=json.load(open('$MAN5'))
for k in ('generated','workspace'): d.pop(k, None)
print(json.dumps(d, sort_keys=True))
" 2>/dev/null | shasum | awk '{print $1}')

# A second run with no ledger changes.
bash "$TOOL" "$WS5" >/dev/null 2>&1
rc5b=$?
HASH_B=$(python3 -c "
import json
d=json.load(open('$MAN5'))
for k in ('generated','workspace'): d.pop(k, None)
print(json.dumps(d, sort_keys=True))
" 2>/dev/null | shasum | awk '{print $1}')
set -e 2>/dev/null || true

if [ "$rc5a" -eq 0 ] && [ "$rc5b" -eq 0 ] && [ "$HASH_A" = "$HASH_B" ] && [ -n "$HASH_A" ]; then
  PASS=$((PASS+1)); echo "PASS: idempotent — manifest content stable across runs (hash=$HASH_A)"
else
  FAIL=$((FAIL+1)); echo "FAIL: manifest content changed across runs"
  echo "  rc5a=$rc5a rc5b=$rc5b HASH_A=$HASH_A HASH_B=$HASH_B"
fi

# ---------------------------------------------------------------------------
# Test 6 — Tool crashes with ImportError (PR #518 follow-up).
#
# Repros Minimax CRITICAL_HANDOFF_BREAK: when invariant-ledger.py raises
# ImportError on import, the manifest is NOT written. Pre-fix audit-deep
# claimed `ran: invariant-ledger-summary` and exited 0. Post-fix:
#   - default mode: exits 0 BUT `ran:` excludes invariant-ledger-summary
#     AND `failed:` includes it
#   - REQUIRE_INVARIANT_LEDGER=1 OR REQUIRE_HIGH_IMPACT_INVARIANTS=1: exit 1
# ---------------------------------------------------------------------------
WS6="$SANDBOX/tool-importerror"; mkdir -p "$WS6/.auditooor"
cat > "$WS6/.auditooor/invariant_ledger.json" <<'JSON'
{
  "schema": "auditooor.invariant_ledger.v1",
  "rows": [
    {"id":"X-I01","scope_asset":"X","invariant_family":"f","statement":"s","status":"executed_clean","required_engine":"forge","owner":"Claude","artifacts":[],"source_citations":["SCOPE.md::X"],"harness_target":"test/X.t.sol"}
  ]
}
JSON

# Build a sandboxed audit-deep that points at a stub invariant-ledger.py
# which raises ImportError on import. We do this by mirroring the real
# tools/ directory into the sandbox via symlinks, then overlaying our
# own invariant-ledger.py stub on top. audit-deep resolves its tool via
# $HERE/invariant-ledger.py so a sibling override is sufficient — and
# the symlinks to lib/ + the other helper scripts keep the rest of
# audit-deep functional.
STUB_HERE="$SANDBOX/stub_tooldir"; mkdir -p "$STUB_HERE"
for entry in "$REPO/tools"/*; do
  bn="$(basename "$entry")"
  ln -s "$entry" "$STUB_HERE/$bn"
done
# Override invariant-ledger.py with a stub that raises ImportError.
rm -f "$STUB_HERE/invariant-ledger.py"
cat > "$STUB_HERE/invariant-ledger.py" <<'PY'
#!/usr/bin/env python3
"""Adversarial stub: raises ImportError on every invocation."""
import nonexistent_module_for_audit_deep_test  # noqa: F401
PY
chmod +x "$STUB_HERE/invariant-ledger.py"

WS6B="$SANDBOX/tool-importerror-2"; mkdir -p "$WS6B/.auditooor"
cp "$WS6/.auditooor/invariant_ledger.json" "$WS6B/.auditooor/"
set +e
out6b=$(bash "$STUB_HERE/audit-deep.sh" "$WS6B" 2>&1); rc6b=$?
set -e 2>/dev/null || true

REPORT6B="$WS6B/.audit_logs/audit_deep_report.md"
if [ "$rc6b" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: broken tool default rc=0 (advisory)"
else
  FAIL=$((FAIL+1)); echo "FAIL: broken tool default expected rc=0, got $rc6b"
fi

# Default-mode `ran:` MUST NOT include invariant-ledger-summary.
if [ -f "$REPORT6B" ] && grep -q '^- ran:' "$REPORT6B" && \
   ! grep -E '^- ran:.*invariant-ledger-summary' "$REPORT6B" >/dev/null 2>&1; then
  PASS=$((PASS+1)); echo "PASS: broken tool default — ran: excludes invariant-ledger-summary"
else
  FAIL=$((FAIL+1)); echo "FAIL: broken tool default — ran: should exclude invariant-ledger-summary"
  grep -E '^- (ran|skipped|failed):' "$REPORT6B" 2>/dev/null | head -5
fi

# Default-mode `failed:` MUST include invariant-ledger-summary.
if [ -f "$REPORT6B" ] && grep -E '^- failed:.*invariant-ledger-summary' "$REPORT6B" >/dev/null 2>&1; then
  PASS=$((PASS+1)); echo "PASS: broken tool default — failed: includes invariant-ledger-summary"
else
  FAIL=$((FAIL+1)); echo "FAIL: broken tool default — failed: missing invariant-ledger-summary"
  grep -E '^- (ran|skipped|failed):' "$REPORT6B" 2>/dev/null | head -5
fi

# Strict env-var promotes broken-tool to exit 1.
WS6C="$SANDBOX/tool-importerror-strict"; mkdir -p "$WS6C/.auditooor"
cp "$WS6/.auditooor/invariant_ledger.json" "$WS6C/.auditooor/"
set +e
out6c=$(REQUIRE_INVARIANT_LEDGER=1 bash "$STUB_HERE/audit-deep.sh" "$WS6C" 2>&1); rc6c=$?
set -e 2>/dev/null || true
if [ "$rc6c" -ne 0 ]; then
  PASS=$((PASS+1)); echo "PASS: broken tool REQUIRE_INVARIANT_LEDGER=1 rc=$rc6c (nonzero)"
else
  FAIL=$((FAIL+1)); echo "FAIL: broken tool strict expected nonzero rc, got 0"
fi

WS6D="$SANDBOX/tool-importerror-strict-hi"; mkdir -p "$WS6D/.auditooor"
cp "$WS6/.auditooor/invariant_ledger.json" "$WS6D/.auditooor/"
set +e
out6d=$(REQUIRE_HIGH_IMPACT_INVARIANTS=1 bash "$STUB_HERE/audit-deep.sh" "$WS6D" 2>&1); rc6d=$?
set -e 2>/dev/null || true
if [ "$rc6d" -ne 0 ]; then
  PASS=$((PASS+1)); echo "PASS: broken tool REQUIRE_HIGH_IMPACT_INVARIANTS=1 rc=$rc6d (nonzero)"
else
  FAIL=$((FAIL+1)); echo "FAIL: broken tool strict-hi expected nonzero, got 0"
fi

# Manifest MUST NOT exist (tool crashed before it could be written).
MANIFEST6B="$WS6B/.audit_logs/invariant_ledger_manifest.json"
if [ ! -f "$MANIFEST6B" ]; then
  PASS=$((PASS+1)); echo "PASS: broken tool — manifest NOT written"
else
  FAIL=$((FAIL+1)); echo "FAIL: broken tool — manifest exists when it should not"
fi

# ---------------------------------------------------------------------------
# Test 7 — Malformed JSON ledger (PR #518 follow-up — Minimax SILENT_ZERO_RISK).
#
# Pre-fix: garbage JSON in invariant_ledger.json was silently treated as
# `[]`, audit-deep wrote a manifest with row_count=0, and even strict
# env-vars didn't catch it. Post-fix: invariant-ledger.py --check raises
# LedgerError on malformed JSON (MM's PR #516 fix), --emit-closeout
# returns rc=1, audit-deep records this as a failed step. Default exits
# 0 with `failed:`; strict env-var exits 1.
# ---------------------------------------------------------------------------
WS7="$SANDBOX/garbage-json"; mkdir -p "$WS7/.auditooor"
printf '{garbage: not-json' > "$WS7/.auditooor/invariant_ledger.json"
set +e
out7=$(bash "$TOOL" "$WS7" 2>&1); rc7=$?
set -e 2>/dev/null || true
if [ "$rc7" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: malformed JSON default rc=0 (advisory)"
else
  FAIL=$((FAIL+1)); echo "FAIL: malformed JSON default expected rc=0, got $rc7"
fi

REPORT7="$WS7/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT7" ] && grep -E '^- failed:.*invariant-ledger-summary' "$REPORT7" >/dev/null 2>&1; then
  PASS=$((PASS+1)); echo "PASS: malformed JSON — failed: includes invariant-ledger-summary"
else
  FAIL=$((FAIL+1)); echo "FAIL: malformed JSON — failed: missing invariant-ledger-summary"
  grep -E '^- (ran|skipped|failed):' "$REPORT7" 2>/dev/null | head -5
fi

WS7B="$SANDBOX/garbage-json-strict"; mkdir -p "$WS7B/.auditooor"
printf '{garbage: not-json' > "$WS7B/.auditooor/invariant_ledger.json"
set +e
out7b=$(REQUIRE_INVARIANT_LEDGER=1 bash "$TOOL" "$WS7B" 2>&1); rc7b=$?
set -e 2>/dev/null || true
if [ "$rc7b" -ne 0 ]; then
  PASS=$((PASS+1)); echo "PASS: malformed JSON REQUIRE_INVARIANT_LEDGER=1 rc=$rc7b (nonzero)"
else
  FAIL=$((FAIL+1)); echo "FAIL: malformed JSON strict expected nonzero, got 0"
fi

WS7C="$SANDBOX/garbage-json-strict-hi"; mkdir -p "$WS7C/.auditooor"
printf '{garbage: not-json' > "$WS7C/.auditooor/invariant_ledger.json"
set +e
out7c=$(REQUIRE_HIGH_IMPACT_INVARIANTS=1 bash "$TOOL" "$WS7C" 2>&1); rc7c=$?
set -e 2>/dev/null || true
if [ "$rc7c" -ne 0 ]; then
  PASS=$((PASS+1)); echo "PASS: malformed JSON REQUIRE_HIGH_IMPACT_INVARIANTS=1 rc=$rc7c (nonzero)"
else
  FAIL=$((FAIL+1)); echo "FAIL: malformed JSON strict-hi expected nonzero, got 0"
fi

# ---------------------------------------------------------------------------
# Test 8 — Zero-byte ledger file (PR #518 follow-up — Minimax NEEDS_FIX #4).
#
# Pre-fix: `: > invariant_ledger.json` was silently treated as zero rows.
# Post-fix: --check fails (LedgerError on JSONDecodeError of empty
# string), --emit-closeout returns rc=1, audit-deep records failed[].
# ---------------------------------------------------------------------------
WS8="$SANDBOX/zero-byte"; mkdir -p "$WS8/.auditooor"
: > "$WS8/.auditooor/invariant_ledger.json"
set +e
out8=$(bash "$TOOL" "$WS8" 2>&1); rc8=$?
set -e 2>/dev/null || true
if [ "$rc8" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: zero-byte ledger default rc=0 (advisory)"
else
  FAIL=$((FAIL+1)); echo "FAIL: zero-byte ledger default expected rc=0, got $rc8"
fi

REPORT8="$WS8/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT8" ] && grep -E '^- failed:.*invariant-ledger-summary' "$REPORT8" >/dev/null 2>&1; then
  PASS=$((PASS+1)); echo "PASS: zero-byte ledger — failed: includes invariant-ledger-summary"
else
  FAIL=$((FAIL+1)); echo "FAIL: zero-byte ledger — failed: missing invariant-ledger-summary"
  grep -E '^- (ran|skipped|failed):' "$REPORT8" 2>/dev/null | head -5
fi

WS8B="$SANDBOX/zero-byte-strict"; mkdir -p "$WS8B/.auditooor"
: > "$WS8B/.auditooor/invariant_ledger.json"
set +e
out8b=$(REQUIRE_HIGH_IMPACT_INVARIANTS=1 bash "$TOOL" "$WS8B" 2>&1); rc8b=$?
set -e 2>/dev/null || true
if [ "$rc8b" -ne 0 ]; then
  PASS=$((PASS+1)); echo "PASS: zero-byte ledger REQUIRE_HIGH_IMPACT_INVARIANTS=1 rc=$rc8b (nonzero)"
else
  FAIL=$((FAIL+1)); echo "FAIL: zero-byte ledger strict expected nonzero, got 0"
fi

# ---------------------------------------------------------------------------
# Test 9 — Closeout reads the audit-deep manifest after a tool crash
# (PR #518 follow-up). When audit-deep had a tool crash it MUST NOT have
# written the manifest — the closeout fallback path then drives WARN/FAIL
# semantics from the ledger directly. We just assert the absence here so
# audit-closeout-check.py's pre-existing fallback test (test_audit_closeout_check.py)
# remains the source of truth for closeout behaviour.
# ---------------------------------------------------------------------------
if [ ! -f "$WS6B/.audit_logs/invariant_ledger_manifest.json" ]; then
  PASS=$((PASS+1)); echo "PASS: closeout handoff — manifest absent after broken-tool run (audit-closeout-check falls back)"
else
  FAIL=$((FAIL+1)); echo "FAIL: closeout handoff — manifest present after broken-tool run (silently overwrote)"
fi

# ---------------------------------------------------------------------------
# Test 10 — Init-only (empty rows) ledger WITH a scope source present is
# seeded via --from-scope BEFORE --emit-closeout, so the closeout succeeds and
# the manifest is written (near-intents 2026-06-25 regression: audit-deep ran
# emit-closeout on an --init-only ledger -> rc=1 "zero rows" -> manifest NOT
# written -> step-2 verify-artifact absent). Guards the from-scope pre-seed.
# ---------------------------------------------------------------------------
WS10="$SANDBOX/init-only-with-scope"; mkdir -p "$WS10/.auditooor" "$WS10/src"
# empty (init-only) ledger
echo '{"schema":"auditooor.invariant_ledger.v1","rows":[]}' > "$WS10/.auditooor/invariant_ledger.json"
# a minimal Solidity scope source so --from-scope has something to seed from
cat > "$WS10/src/Vault.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    function initialize() external { owner = msg.sender; }
    function upgradeTo(address impl) external { /* missing onlyOwner */ }
}
EOF
cat > "$WS10/SCOPE.md" <<'EOF'
# Scope
In-scope: src/Vault.sol (Vault) - upgrade authorization, initializer guard.
EOF

set +e
out10=$(bash "$TOOL" "$WS10" 2>&1); rc10=$?
set -e 2>/dev/null || true
if [ "$rc10" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: init-only ledger + scope -> audit-deep exits 0"
else
  FAIL=$((FAIL+1)); echo "FAIL: init-only+scope expected rc=0, got $rc10"
  echo "----- output -----"; echo "$out10" | tail -20; echo "------------------"
fi
# The load-bearing fix: an EMPTY ledger triggers the --from-scope pre-closeout
# seed (the wiring that was missing). We assert the wiring deterministically -
# whether --from-scope finds seedable candidates depends on the workspace's
# engage-report/detector intel, which is out of scope for this unit (near-intents
# 2026-06-25 seeded 51 rows from a real engage report; a bare sandbox seeds 0).
# What MUST hold for every empty ledger is that the seed step RAN before closeout.
REPORT10="$WS10/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT10" ] && grep -q "ledger rows: 0 (empty); running --from-scope pre-closeout seed" "$REPORT10"; then
  PASS=$((PASS+1)); echo "PASS: empty ledger triggers --from-scope pre-closeout seed (wiring present)"
else
  FAIL=$((FAIL+1)); echo "FAIL: empty ledger did not trigger --from-scope pre-closeout seed"
  [ -f "$REPORT10" ] && grep -E "ledger rows|from-scope|emit-closeout" "$REPORT10" | head -5
fi
# Ordering: the from-scope seed line MUST precede the emit-closeout line.
if [ -f "$REPORT10" ]; then
  seed_ln=$(grep -n -- "running --from-scope pre-closeout seed" "$REPORT10" | head -1 | cut -d: -f1)
  emit_ln=$(grep -n -- "--emit-closeout" "$REPORT10" | head -1 | cut -d: -f1)
  if [ -n "$seed_ln" ] && [ -n "$emit_ln" ] && [ "$seed_ln" -lt "$emit_ln" ]; then
    PASS=$((PASS+1)); echo "PASS: --from-scope seed (line $seed_ln) runs before --emit-closeout (line $emit_ln)"
  else
    FAIL=$((FAIL+1)); echo "FAIL: from-scope/emit-closeout ordering wrong (seed=$seed_ln emit=$emit_ln)"
  fi
fi
# Populated-ledger guard: a ledger with existing rows must NOT be re-seeded
# (preserve operator-curated rows / no row-count drift). Test 3's WS3 has 3 rows.
REPORT3B="$WS3/.audit_logs/audit_deep_report.md"
if [ -f "$REPORT3B" ] && grep -q "populated); skipping --from-scope seed" "$REPORT3B"; then
  PASS=$((PASS+1)); echo "PASS: populated ledger skips --from-scope seed (no row-count drift)"
else
  FAIL=$((FAIL+1)); echo "FAIL: populated ledger did not skip from-scope seed"
  [ -f "$REPORT3B" ] && grep -E "ledger rows|from-scope" "$REPORT3B" | head -3
fi

echo ""
echo "[test_audit_deep_invariant_ledger_wiring] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
