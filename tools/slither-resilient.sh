#!/usr/bin/env bash
# slither-resilient.sh — wrap `slither` invocations with explicit exit codes (Issue #99).
#
# Classifies failures into: OK / HIT / NO_HIT / TIMEOUT / COMPILE_ERR / FATAL.
# Lets fixture-CI distinguish real regressions from compiler hiccups.
#
# Usage:
#   ./tools/slither-resilient.sh [--timeout N] [--detect DETECTOR] -- <slither-args>
#
# Exit codes:
#   0 — Slither ran clean, no detector fired (NO_HIT)
#   1 — Slither ran, detector fired (HIT)
#  10 — Compile error (solc failed)
#  11 — Timeout
#  12 — Slither internal fatal (segfault / Python exception)
#  99 — Invalid usage

set -u

TIMEOUT_S=60
DETECTOR=""
POSITIONAL=()

while [ $# -gt 0 ]; do
  case "$1" in
    --timeout) TIMEOUT_S="$2"; shift 2 ;;
    --detect) DETECTOR="$2"; shift 2 ;;
    --) shift; break ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
POSITIONAL+=("$@")

if [ ${#POSITIONAL[@]} -eq 0 ]; then
  echo "usage: $0 [--timeout N] [--detect DET] -- <slither-target> [args...]" >&2
  exit 99
fi

# Decide on timeout command (macOS has no timeout by default; use perl fallback)
run_with_timeout() {
  local secs="$1"; shift
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
    return $?
  elif command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
    return $?
  else
    # perl-based fallback: exits 124 on timeout
    perl -e 'alarm(shift @ARGV); exec @ARGV' "$secs" "$@"
    local rc=$?
    [ $rc = 142 ] && return 124
    return $rc
  fi
}

TMP_STDOUT=$(mktemp)
TMP_STDERR=$(mktemp)
trap 'rm -f "$TMP_STDOUT" "$TMP_STDERR"' EXIT

ARGS=("${POSITIONAL[@]}")
[ -n "$DETECTOR" ] && ARGS+=("--detect" "$DETECTOR")

run_with_timeout "$TIMEOUT_S" slither "${ARGS[@]}" > "$TMP_STDOUT" 2> "$TMP_STDERR"
RC=$?

if [ $RC = 124 ] || [ $RC = 137 ]; then
  echo "TIMEOUT" >&2
  exit 11
fi

# Slither returns 0 if no issues, 255 / other if issues found. Inspect stderr for common failure strings.
if grep -qE "(solc.*(not found|unsupported|Invalid|failed))|(SyntaxError|ParserError)|(No compilation unit)" "$TMP_STDERR" 2>/dev/null; then
  echo "COMPILE_ERR" >&2
  cat "$TMP_STDERR" >&2
  exit 10
fi

if grep -qE "(Traceback|AttributeError|KeyError|AssertionError|SystemError)" "$TMP_STDERR" 2>/dev/null; then
  echo "FATAL" >&2
  cat "$TMP_STDERR" >&2
  exit 12
fi

# Detect actual findings — Slither prints "(high-severity)" / "(medium)" / "(low-severity)"
if grep -qiE '^\s*\[.*\].*—|(high|medium|low|info)-severity' "$TMP_STDOUT" 2>/dev/null; then
  cat "$TMP_STDOUT"
  exit 1   # HIT
fi

exit 0     # NO_HIT
