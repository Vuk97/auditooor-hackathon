#!/usr/bin/env bash
# Rank-1 (NUVA presubmit friction): PoC-first fail-fast (Check #10p).
#
# For HIGH/CRITICAL drafts the pre-submit gate must refuse to run the long
# *format* body (Checks #12+) until the PoC *substance* is green. This test
# proves both directions:
#   TP1  single-process CRITICAL cosmos consensus-halt (no probe artifact,
#        in-process-only PoC) -> exit 1, banner printed, format body SKIPPED.
#   FP1  an l32-rebuttal marker DEFERS the fail-fast (no early exit; the late
#        Check #58 still adjudicates the same rebuttal).
#   FP2  a genuine multi-node PoC (probe artifact present + node-level
#        FinalizeBlock/commit evidence) passes the fail-fast, format body RUNS.
#   NP1  a Medium draft is a no-op (the block only fires for High/Critical).
#   NP2  default-OFF: a bare CLI run (env NOT set) does not fail-fast even for a
#        substance-missing CRITICAL (plain lint runs are unchanged).
#   WIRE the paste-ready invoker exports AUDITOOOR_POC_FIRST_STRICT so the
#        block is not inert (mandatory revision #2).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/../pre-submit-check.sh"
GEN="$SCRIPT_DIR/../paste-ready-generator.py"
BANNER='ORDER OF OPERATIONS'          # unique to the 10p banner
# Check #12 output line (e.g. "  ✅ 12. No extreme-value ...") == format body
# ran. The status emoji sits between the leading spaces and "12.", so match the
# number token with optional leading noise, not a strict line-start.
FORMAT_MARKER_RE='(^|[[:space:]])12\. '
POC_FIRST_MARKER='10p.'
fail() { echo "FAIL: $1" >&2; exit 1; }
format_body_ran() { printf '%s' "$1" | grep -qE "$FORMAT_MARKER_RE"; }

WORK="$(mktemp -d /tmp/poc_first_test_XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
# workspace-root markers so the script's WS_ROOT walk anchors here
mkdir -p "$WORK/poc-tests"
: > "$WORK/AUDIT.md"

# ---- run helper: arms the block via env, captures stdout+stderr+rc ----------
run_armed() {  # $1 draft
    AUDITOOOR_POC_FIRST_STRICT=1 bash "$CHECK" "$1" 2>&1
}
run_bare() {   # $1 draft (env NOT set)
    bash "$CHECK" "$1" 2>&1
}

# ---------------------------------------------------------------------------
# TP1 - CRITICAL single-process consensus-halt: MUST fail-fast, skip format.
# ---------------------------------------------------------------------------
cat > "$WORK/tp1_critical.md" <<'MD'
# Consensus halt in x/swap MsgSwapOut leads to chain halt

**Severity:** Critical

## Summary
A crafted MsgSwapOut halts the chain (consensus halt / network halt). The whole
network stops producing blocks; this is a node-level liveness failure.

## Proof of Concept
```go
func TestSwapOutPanic(t *testing.T) {
    // in-process keeper-only unit test; no validator set, no FinalizeBlock
    k, ctx := setupKeeper(t)
    require.Panics(t, func() { k.SwapOut(ctx, badMsg) })
}
```
MD
out="$(run_armed "$WORK/tp1_critical.md")"; rc=$?
[ "$rc" -eq 1 ] || fail "TP1 expected exit 1, got $rc"
echo "$out" | grep -q "$BANNER" || fail "TP1 banner missing"
echo "$out" | grep -q 'cosmos_multivalidator_probe_shell.py' || fail "TP1 harness pointer missing"
# format body (Check #12) MUST be absent -- fail-fast short-circuited it
if format_body_ran "$out"; then fail "TP1 format body ran (Check #12 seen) - fail-fast did not short-circuit"; fi
echo "  ok TP1: CRITICAL single-process consensus-halt -> exit 1 + banner + format SKIPPED"

# ---------------------------------------------------------------------------
# FP1 (CONTROL / suppression) - same draft + l32-rebuttal DEFERS the fail-fast.
# The existing marker is reused; no early exit; late #58 still adjudicates it.
# ---------------------------------------------------------------------------
cat > "$WORK/fp1_rebuttal.md" <<'MD'
# Consensus halt in x/swap MsgSwapOut leads to chain halt

**Severity:** Critical

<!-- l32-rebuttal: source-backed exception - ADR-27 documents the single-node repro is representative; multi-validator run deferred to fork-replay -->

## Summary
A crafted MsgSwapOut halts the chain (consensus halt / network halt).

## Proof of Concept
```go
func TestSwapOutPanic(t *testing.T) {
    k, ctx := setupKeeper(t)
    require.Panics(t, func() { k.SwapOut(ctx, badMsg) })
}
```
MD
out="$(run_armed "$WORK/fp1_rebuttal.md")"; rc=$?
# Deferred: 10p must NOT be the reason for an early exit-1. The banner must be absent.
echo "$out" | grep -q "$BANNER" && fail "FP1 fail-fast banner fired despite l32-rebuttal (not deferred)"
echo "$out" | grep -qE '10p\..*deferred via l32-rebuttal' || fail "FP1 deferral advisory missing"
# format body must have RUN (the block deferred, did not exit)
format_body_ran "$out" || fail "FP1 format body did not run after deferral"
echo "  ok FP1: l32-rebuttal DEFERS fail-fast (no banner, format body runs)"

# ---------------------------------------------------------------------------
# FP2 (suppression) - genuine multi-node PoC: probe artifact + node-level
# evidence -> substance GREEN, no fail-fast, format body runs.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/poc-tests/candidate"
cat > "$WORK/poc-tests/candidate/multivalidator_probe_test.go" <<'GO'
package harness
// generated by cosmos_multivalidator_probe_shell.py (stub artifact)
func TestMultiValidatorAppHash(t *testing.T) {}
GO
cat > "$WORK/fp2_multinode.md" <<'MD'
# Consensus halt in x/swap MsgSwapOut leads to chain halt

**Severity:** Critical

## Summary
A crafted MsgSwapOut halts the chain (consensus halt / network halt).

## Proof of Concept
Ran across a 4-validator network; the divergence is observed at the node level
via FinalizeBlock + Commit across all validators (AppHash divergence). See
poc-tests/candidate/multivalidator_probe_test.go.

```go
func TestSwapOutHaltNodeLevel(t *testing.T) {
    // 4-validator network: FinalizeBlock, Commit, restart-survival
    net := newMultiValidatorNet(t, 4)
    net.FinalizeBlock(badBlock)
    net.Commit()
    require.True(t, net.Halted())
}
```
MD
out="$(run_armed "$WORK/fp2_multinode.md")"; rc=$?
echo "$out" | grep -q "$BANNER" && fail "FP2 fail-fast fired on a genuine multi-node PoC (false positive)"
echo "$out" | grep -qE '10p\..*PoC substance green' || fail "FP2 substance-green line missing"
format_body_ran "$out" || fail "FP2 format body did not run for a green multi-node PoC"
echo "  ok FP2: genuine multi-node PoC passes fail-fast, format body runs"

# ---------------------------------------------------------------------------
# NP1 - Medium draft is a no-op (block only fires for High/Critical).
# ---------------------------------------------------------------------------
cat > "$WORK/np1_medium.md" <<'MD'
# Consensus halt claim (medium)

**Severity:** Medium

## Summary
consensus halt / network halt claim with only an in-process keeper unit test.

## Proof of Concept
```go
func TestX(t *testing.T) {}
```
MD
out="$(run_armed "$WORK/np1_medium.md")"; rc=$?
echo "$out" | grep -q "$BANNER" && fail "NP1 fail-fast fired for a Medium draft"
if echo "$out" | grep -q "$POC_FIRST_MARKER"; then fail "NP1 10p block ran for a Medium draft"; fi
echo "  ok NP1: Medium draft is a no-op"

# ---------------------------------------------------------------------------
# NP2 - default-OFF: bare CLI run (env NOT set) must not fail-fast even when
#       substance is missing (plain lint runs unchanged).
# ---------------------------------------------------------------------------
out="$(run_bare "$WORK/tp1_critical.md")"; rc=$?
echo "$out" | grep -q "$BANNER" && fail "NP2 fail-fast fired on a bare CLI run (should be default-off)"
if echo "$out" | grep -q "$POC_FIRST_MARKER"; then fail "NP2 10p block ran without the arming env"; fi
echo "  ok NP2: default-OFF for a bare CLI invocation"

# ---------------------------------------------------------------------------
# WIRE - the paste-ready invoker exports the arming env (mandatory revision 2).
# ---------------------------------------------------------------------------
grep -q 'AUDITOOOR_POC_FIRST_STRICT' "$GEN" \
    || fail "WIRE: paste-ready-generator.py does not export AUDITOOOR_POC_FIRST_STRICT (block would be inert)"
grep -q 'env=_env' "$GEN" \
    || fail "WIRE: paste-ready-generator.py does not pass env= to the pre-submit subprocess"
echo "  ok WIRE: paste-ready invoker arms the block (not inert under STRICT)"

echo "PASS: PoC-first fail-fast (10p) - fires on genuine reliance, suppressed on rebuttal/multi-node/Medium/bare-CLI"
