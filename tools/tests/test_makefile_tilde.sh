#!/usr/bin/env bash
# test_makefile_tilde.sh — regression test for I-01 (Makefile audit-target
# tilde-expand) and Q-01 (auto-mkdir of <ws>/.audit_logs/).
#
# Make does NOT tilde-expand variable values, so before the fix
# `make audit WS=~/audits/foo DRY_RUN=1` would fail the existence check
# even when the directory existed. This test scaffolds a fake $HOME/audits/<x>
# under a tempdir, points HOME at it, and asserts:
#   1. `make audit WS=~/audits/<x> DRY_RUN=1` exits 0 (tilde-expand worked).
#   2. <ws>/.audit_logs/ exists after the run (Q-01 auto-mkdir).
#   3. `make audit WS=~user/foo` does NOT silently splice $HOME with the
#      remainder (no `getpwnam` in make) — must report the verbatim path
#      `~user/foo` and exit non-zero. This is the Minimax PR #163 bug:
#      the original `filter ~%` arm matched `~user/foo` and produced
#      `$(HOME)user/foo` (no slash, e.g. /Users/wolfuser/foo).
#   4. `make audit WS=~` (bare tilde) resolves to $HOME and exits 0.
#
# Path-resolution assertions go through the dedicated `make print-ws-resolved`
# target (which emits `[print-ws-resolved] <resolved-path>` and nothing else),
# so the test is decoupled from audit-progress.py / engage.py log formats —
# Kimi K3 review of PR #171 flagged the original artifact-path greps as
# brittle fixture dependencies on those logs.
#
# Run:
#   bash tools/tests/test_makefile_tilde.sh
#
# Skips cleanly if make/python3 are unavailable. No network.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if ! command -v make >/dev/null 2>&1; then
  echo "[test_makefile_tilde] SKIP: make not on PATH"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[test_makefile_tilde] SKIP: python3 not on PATH"
  exit 0
fi

FAIL=0
PASS=0

# Sandbox HOME so the test does not touch the operator's real ~/audits/.
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/audits/morpho-test/docs"
touch "$SANDBOX/audits/morpho-test/docs/SCOPE.md"
# WS-resolve-guard.sh (fail-loud stub check) requires a workspace marker or
# source file to accept a resolved path as a real audit workspace, not just
# `-d`. Also stamp a marker directly under $SANDBOX itself since the "bare ~"
# case below resolves WS to $SANDBOX (not $SANDBOX/audits/morpho-test).
mkdir -p "$SANDBOX/docs"
touch "$SANDBOX/docs/SCOPE.md"

# Run from the repo so `make audit` uses the local Makefile.
cd "$REPO"

# DRY_RUN=1 short-circuits engage.py; it should print [engage] DRY-RUN ...
# and exit 0 if tilde-expansion worked. If make can't resolve ~ it would
# instead exit 2 with "[make audit] ERR workspace not found".
out="$(HOME="$SANDBOX" make audit WS='~/audits/morpho-test' DRY_RUN=1 2>&1)"
rc=$?

if [ "$rc" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: I-01 tilde-expand — make audit WS=~/audits/<x> DRY_RUN=1 exit 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: I-01 tilde-expand — exit $rc"
  echo "----- output -----"
  echo "$out"
  echo "------------------"
fi

# Make-level resolved path must equal $SANDBOX/audits/morpho-test. Use the
# dedicated `print-ws-resolved` target (added alongside this refactor) so the
# assertion lives at the make layer and is independent of audit-progress.py /
# engage.py log formats (Kimi K3 PR #171 review). Format:
#     [print-ws-resolved] <resolved-path>
out_resolved="$(HOME="$SANDBOX" make -s print-ws-resolved WS='~/audits/morpho-test' 2>&1)"
expected="[print-ws-resolved] $SANDBOX/audits/morpho-test"
if [ "$out_resolved" = "$expected" ]; then
  PASS=$((PASS+1))
  echo "PASS: I-01 tilde-expand — make-resolved \$(WS) == $SANDBOX/audits/morpho-test"
else
  FAIL=$((FAIL+1))
  echo "FAIL: I-01 tilde-expand — make-resolved \$(WS) mismatch"
  echo "  expected: $expected"
  echo "  got:      $out_resolved"
fi

# Q-01: .audit_logs/ should have been auto-created.
if [ -d "$SANDBOX/audits/morpho-test/.audit_logs" ]; then
  PASS=$((PASS+1))
  echo "PASS: Q-01 mkdir — <ws>/.audit_logs/ created"
else
  FAIL=$((FAIL+1))
  echo "FAIL: Q-01 mkdir — <ws>/.audit_logs/ missing"
fi

# Minimax PR #163 review: `WS=~user/foo` must NOT splice $HOME with `user/foo`.
# Make has no getpwnam, so we leave `~user/...` as-is and let the existence
# check report the unresolvable path verbatim. The buggy form would emit
# `$(HOME)user/foo` (e.g. /Users/wolfuser/foo) and the ERR line would
# contain the SANDBOX prefix glued to `user/foo`. The fixed form must
# print `~user/foo` literally in the ERR line.
out_user="$(HOME="$SANDBOX" make audit WS='~user/foo' DRY_RUN=1 2>&1)"
rc_user=$?

if [ "$rc_user" -ne 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: ~user/foo — make audit exits non-zero (got $rc_user)"
else
  FAIL=$((FAIL+1))
  echo "FAIL: ~user/foo — expected non-zero exit, got 0"
  echo "----- output -----"
  echo "$out_user"
  echo "------------------"
fi

if echo "$out_user" | grep -qF '~user/foo'; then
  PASS=$((PASS+1))
  echo "PASS: ~user/foo — verbatim path appears in ERR line (no \$HOME splice)"
else
  FAIL=$((FAIL+1))
  echo "FAIL: ~user/foo — verbatim path missing; suggests \$HOME was spliced"
  echo "----- output -----"
  echo "$out_user"
  echo "------------------"
fi

# The buggy form would produce `${SANDBOX}user/foo` (no slash). Assert that
# this exact bad concatenation is absent. Use the resolved $SANDBOX (no
# trailing slash) directly concatenated to `user/foo`.
bad_splice="${SANDBOX}user/foo"
if echo "$out_user" | grep -qF "$bad_splice"; then
  FAIL=$((FAIL+1))
  echo "FAIL: ~user/foo — found bad \$HOME splice in output: $bad_splice"
  echo "----- output -----"
  echo "$out_user"
  echo "------------------"
else
  PASS=$((PASS+1))
  echo "PASS: ~user/foo — no bad \$HOME splice ('${bad_splice}' not in output)"
fi

# Bare `~` should resolve to $HOME (= $SANDBOX here) and exit 0. The sandbox
# itself is a directory, so the existence check passes.
out_bare="$(HOME="$SANDBOX" make audit WS='~' DRY_RUN=1 2>&1)"
rc_bare=$?

if [ "$rc_bare" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: bare ~ — make audit WS=~ DRY_RUN=1 exit 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: bare ~ — exit $rc_bare"
  echo "----- output -----"
  echo "$out_bare"
  echo "------------------"
fi

# Resolved path for bare `~` must be exactly $SANDBOX. Assert via the
# `print-ws-resolved` make target instead of grepping audit-progress.py
# stage-list output (Kimi K3 PR #171 review — that output format is volatile
# and would silently break this test if engage's log shape changes).
out_bare_resolved="$(HOME="$SANDBOX" make -s print-ws-resolved WS='~' 2>&1)"
expected_bare="[print-ws-resolved] $SANDBOX"
if [ "$out_bare_resolved" = "$expected_bare" ]; then
  PASS=$((PASS+1))
  echo "PASS: bare ~ — make-resolved \$(WS) == \$HOME ($SANDBOX)"
else
  FAIL=$((FAIL+1))
  echo "FAIL: bare ~ — make-resolved \$(WS) mismatch"
  echo "  expected: $expected_bare"
  echo "  got:      $out_bare_resolved"
fi

echo ""
echo "[test_makefile_tilde] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
