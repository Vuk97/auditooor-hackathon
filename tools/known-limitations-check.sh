#!/usr/bin/env bash
#
# known-limitations-check.sh — single-entry burn-down gate aggregator.
#
# Runs the lint flags + focused unit tests that close out or precisely account
# for items in docs/KNOWN_LIMITATIONS.md (P1-1, P1-4, and adjacent rows).
# Prints one PASS/WARN/FAIL line per check and a summary at the end.
#
# Exit codes:
#   0   all FAIL-level checks passed (WARN allowed in default mode)
#   1   at least one FAIL-level check failed
#   2   harness error (missing python3, etc.)
#
# Modes:
#   STRICT=0 (default) — burn-down detector-lint flags are advisory:
#                        non-zero from those flags is reported as WARN
#                        and does NOT flip the overall rc. The default
#                        lint pass and the focused unit tests are always
#                        FAIL-level.
#   STRICT=1           — every detector-lint flag failure is promoted to
#                        FAIL. Adds the audit_closeout regression test
#                        to the unit test set.
#
# Operator usage:
#   make known-limitations-check
#   make known-limitations-check STRICT=1
#
# CI guidance: wire this advisory-only into `make ci` first; promote to
# mandatory in a separate PR once the burn-down items reach zero.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

STRICT="${STRICT:-0}"

# ANSI colors are only emitted to a tty; CI logs stay plain.
if [ -t 1 ]; then
  C_RESET="\033[0m"; C_BOLD="\033[1m"
  C_PASS="\033[32m"; C_WARN="\033[33m"; C_FAIL="\033[31m"
else
  C_RESET=""; C_BOLD=""; C_PASS=""; C_WARN=""; C_FAIL=""
fi

# Gate result accumulator. Each row is "<status>|<label>".
RESULTS=()
HARD_FAILS=0
SOFT_WARNS=0

_record() {
  local status="$1"; shift
  local label="$*"
  RESULTS+=("${status}|${label}")
  case "$status" in
    PASS) printf "  ${C_PASS}[PASS]${C_RESET} %s\n" "$label" ;;
    WARN) printf "  ${C_WARN}[WARN]${C_RESET} %s\n" "$label" ; SOFT_WARNS=$((SOFT_WARNS + 1)) ;;
    FAIL) printf "  ${C_FAIL}[FAIL]${C_RESET} %s\n" "$label" ; HARD_FAILS=$((HARD_FAILS + 1)) ;;
  esac
}

# Run a detector-lint flag. In default mode any non-zero is WARN
# (advisory); in STRICT mode it is FAIL.
_run_lint() {
  local label="$1"; shift
  # All remaining args are passed to detector-lint.py.
  local rc=0
  python3 tools/detector-lint.py "$@" >/tmp/known_limitations_check.lint.log 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    _record "PASS" "$label"
  else
    if [ "$STRICT" = "1" ]; then
      _record "FAIL" "$label (rc=$rc; see /tmp/known_limitations_check.lint.log)"
    else
      _record "WARN" "$label (rc=$rc; advisory in non-STRICT mode)"
    fi
  fi
}

# Run a unittest set. Always FAIL on non-zero.
_run_unittests() {
  local label="$1"; shift
  local rc=0
  python3 -m unittest "$@" >/tmp/known_limitations_check.tests.log 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    _record "PASS" "$label"
  else
    _record "FAIL" "$label (rc=$rc; see /tmp/known_limitations_check.tests.log)"
  fi
}

if ! command -v python3 >/dev/null 2>&1; then
  printf "%berror%b: python3 not found on PATH\n" "$C_FAIL" "$C_RESET" >&2
  exit 2
fi

printf "${C_BOLD}known-limitations-check${C_RESET}  STRICT=%s\n" "$STRICT"
printf "Burn-down gates from docs/KNOWN_LIMITATIONS.md (P1-1 / P1-4)\n"
printf "\n${C_BOLD}1/2 detector-lint gates${C_RESET}\n"

# Default lint pass — HIGH-tier disk/script mismatches always FAIL the
# tool, so this stays FAIL-level even in non-STRICT mode.
_lint_default_rc=0
python3 tools/detector-lint.py >/tmp/known_limitations_check.lint.log 2>&1 || _lint_default_rc=$?
if [ "$_lint_default_rc" -eq 0 ]; then
  _record "PASS" "detector-lint (default; HIGH-tier disk/script mismatches)"
else
  _record "FAIL" "detector-lint (default; rc=${_lint_default_rc}; see /tmp/known_limitations_check.lint.log)"
fi

_run_lint "detector-lint --fail-unknown-function-kind" --fail-unknown-function-kind
_run_lint "detector-lint --fail-high-tier-regex-only" --fail-high-tier-regex-only
_run_lint "detector-lint --fail-high-tier-placeholder-fp-guards" --fail-high-tier-placeholder-fp-guards

printf "\n${C_BOLD}2/2 focused unit tests${C_RESET}\n"
_run_unittests "function-kind + placeholder-FP-guard lint tests" \
  tools.tests.test_function_kind_lint \
  tools.tests.test_placeholder_fp_guard_lint \
  tools.tests.test_function_kind_engine_composites

_run_unittests "known-limitations burn-down accounting tests" \
  tools.tests.test_automation_closure.AutomationClosureTests.test_known_limitations_burndown_artifact \
  tools.tests.test_automation_closure.AutomationClosureTests.test_known_limitations_burndown_strict_fails_missing_current_row_fields \
  tools.tests.test_automation_closure.AutomationClosureTests.test_known_limitations_burndown_strict_passes_complete_current_row

if [ "$STRICT" = "1" ]; then
  _run_unittests "audit-closeout regression (STRICT)" tools.tests.test_audit_closeout_check
fi

# ── Summary ─────────────────────────────────────────────────────────────────
printf "\n${C_BOLD}Summary${C_RESET}\n"
for row in "${RESULTS[@]}"; do
  status="${row%%|*}"
  label="${row#*|}"
  case "$status" in
    PASS) printf "  ${C_PASS}PASS${C_RESET}  %s\n" "$label" ;;
    WARN) printf "  ${C_WARN}WARN${C_RESET}  %s\n" "$label" ;;
    FAIL) printf "  ${C_FAIL}FAIL${C_RESET}  %s\n" "$label" ;;
  esac
done
printf "\n  total: %d  pass: %d  warn: %d  fail: %d\n" \
  "${#RESULTS[@]}" \
  "$(( ${#RESULTS[@]} - SOFT_WARNS - HARD_FAILS ))" \
  "$SOFT_WARNS" \
  "$HARD_FAILS"

if [ "$HARD_FAILS" -gt 0 ]; then
  printf "\n${C_FAIL}known-limitations-check: FAIL${C_RESET}\n"
  exit 1
fi

if [ "$SOFT_WARNS" -gt 0 ] && [ "$STRICT" = "1" ]; then
  # Defensive: STRICT promotion already converted WARN to FAIL above, so
  # this branch should be unreachable. Keep the guard for clarity.
  printf "\n${C_FAIL}known-limitations-check: FAIL (STRICT mode, %d warnings)${C_RESET}\n" "$SOFT_WARNS"
  exit 1
fi

if [ "$SOFT_WARNS" -gt 0 ]; then
  printf "\n${C_PASS}known-limitations-check: PASS${C_RESET} (%d advisory WARN — re-run with STRICT=1 to promote)\n" "$SOFT_WARNS"
else
  printf "\n${C_PASS}known-limitations-check: PASS${C_RESET}\n"
fi
exit 0
