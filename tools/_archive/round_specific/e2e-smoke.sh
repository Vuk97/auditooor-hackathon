#!/usr/bin/env bash
# e2e-smoke.sh — full-flow smoke test (Issue #91).
#
# Runs the canonical skill-user flow end-to-end against an existing workspace
# and asserts every expected artifact exists. Exit non-zero on any miss.
#
# Usage: ./tools/e2e-smoke.sh <workspace>

set -u
WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <workspace>" >&2
  exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

check() {
  local name="$1"
  local cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    echo "  ✓ $name"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $name"
    FAIL=$((FAIL + 1))
  fi
}

echo "── Phase 0: workspace scaffolding ──"
check "SCOPE.md exists" "[ -f '$WS/SCOPE.md' ]"
check "SESSION_LOG.md exists" "[ -f '$WS/SESSION_LOG.md' ]"
check "FINDINGS.md exists" "[ -f '$WS/FINDINGS.md' ]"
check "PRIOR_CONCERNS.md exists" "[ -f '$WS/PRIOR_CONCERNS.md' ]"
check "RUBRIC_COVERAGE.md exists" "[ -f '$WS/RUBRIC_COVERAGE.md' ]"

echo
echo "── Tool availability ──"
for t in setup-workspace.sh fetch-scope.sh init-rubric-coverage.sh pre-iter-check.sh \
         scan.sh record-triage.sh pre-submit-check.sh post-audit-review.sh iter-dashboard.sh; do
  check "tools/$t executable" "[ -x '$AUDITOOOR_DIR/tools/$t' ]"
done

echo
echo "── Engine + DSL ──"
check "predicate engine imports" "python3 -c 'import sys; sys.path.insert(0, \"$AUDITOOOR_DIR\"); import detectors._predicate_engine'"
check "wave17 detector count > 100" "[ \$(ls '$AUDITOOOR_DIR/detectors/wave17/' | grep -c '.py\$') -gt 100 ]"
check "patterns.dsl count > 100" "[ \$(ls '$AUDITOOOR_DIR/reference/patterns.dsl/' | grep -c '.yaml\$') -gt 100 ]"

echo
echo "── Observability ──"
check "iter-dashboard.sh runs" "$AUDITOOOR_DIR/tools/iter-dashboard.sh '$WS'"
if [ -x "$AUDITOOOR_DIR/tools/pattern-coverage.py" ]; then
  check "pattern-coverage.py runs" "python3 $AUDITOOOR_DIR/tools/pattern-coverage.py >/dev/null"
fi
if [ -x "$AUDITOOOR_DIR/tools/gen-predicate-docs.py" ]; then
  check "gen-predicate-docs.py --stdout" "python3 $AUDITOOOR_DIR/tools/gen-predicate-docs.py --stdout"
fi

echo
echo "── Summary ──"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [ $FAIL -gt 0 ]; then
  exit 1
fi
exit 0
