#!/usr/bin/env bash
# Smoke-test Makefile wiring for provider-fanout-discipline-check.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if ! command -v make >/dev/null 2>&1; then
  echo "[test_provider_fanout_discipline_makefile] SKIP: make not on PATH"
  exit 0
fi

FAIL=0
PASS=0
WS="$(mktemp -d)"
trap 'rm -rf "$WS"' EXIT
cd "$REPO"

out="$(make -n provider-fanout-discipline-check WS="$WS" JSON=1 ENFORCE_IF_ARTIFACTS=1 2>&1)"
rc=$?

if [ "$rc" -eq 0 ]; then
  PASS=$((PASS+1))
  echo "PASS: dry-run target exits 0"
else
  FAIL=$((FAIL+1))
  echo "FAIL: dry-run target rc=$rc"
  echo "$out"
fi

for needle in \
  "python3 tools/provider-fanout-discipline-check.py" \
  "--workspace \"$WS\"" \
  "--enforce-if-provider-artifacts" \
  "--json"
do
  if echo "$out" | grep -qF -- "$needle"; then
    PASS=$((PASS+1))
    echo "PASS: output contains $needle"
  else
    FAIL=$((FAIL+1))
    echo "FAIL: output missing $needle"
    echo "$out"
  fi
done

lines="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
if [ "$lines" -lt 20 ]; then
  PASS=$((PASS+1))
  echo "PASS: dry-run output stays small ($lines lines)"
else
  FAIL=$((FAIL+1))
  echo "FAIL: dry-run output too noisy ($lines lines)"
fi

echo "[test_provider_fanout_discipline_makefile] PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
