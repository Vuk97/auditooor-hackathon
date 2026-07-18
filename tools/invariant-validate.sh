#!/usr/bin/env bash
# invariant-validate.sh — actually RUN the Foundry invariant harnesses
# produced by gen-invariants.sh. Closes Issue #115 (gen-invariants.sh +
# invariant_templates.yaml shipped in R37 but were never end-to-end invoked).
#
# Walks <ws>/poc-tests/Invariant_*.t.sol, locates the nearest foundry.toml
# ancestor for each harness, and runs `forge test --invariant` with a
# per-harness log. Results are summarised into
# <ws>/invariant_hunt/validate_<ts>.report.md with PASS / FAIL / BROKEN rows
# that flow-gate.sh step 14 already knows how to read.
#
# Usage:
#   ./tools/invariant-validate.sh <workspace> [--runs N] [--depth D]
#
# Exit codes:
#   0 — all harnesses green OR no harnesses found
#   1 — at least one harness reported a BROKEN / failing invariant
#   2 — usage / environment error
set -u

WS="${1:-}"
RUNS=10000
DEPTH=50
shift 1 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --runs)  RUNS="$2";  shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    -h|--help)
      echo "usage: $0 <workspace> [--runs N] [--depth D]" >&2; exit 2 ;;
    *) shift ;;
  esac
done

if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <workspace> [--runs N] [--depth D]" >&2
  exit 2
fi

if ! command -v forge >/dev/null 2>&1; then
  echo "[invariant-validate] forge not in PATH — install foundry first" >&2
  exit 2
fi

HARNESS_DIR="$WS/poc-tests"
if [ ! -d "$HARNESS_DIR" ]; then
  echo "[invariant-validate] no poc-tests/ directory — run gen-invariants.sh first" >&2
  exit 0
fi

HARNESSES=$(ls "$HARNESS_DIR"/Invariant_*.t.sol 2>/dev/null || true)
if [ -z "$HARNESSES" ]; then
  echo "[invariant-validate] no Invariant_*.t.sol harnesses found — run gen-invariants.sh first" >&2
  exit 0
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$WS/invariant_hunt"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/validate_${TS}.report.md"

{
  echo "# Invariant validate — $(basename "$WS") @ $TS"
  echo
  echo "| harness | project_root | status | notes |"
  echo "|---|---|---|---|"
} > "$REPORT"

FAILS=0
for H in $HARNESSES; do
  STEM=$(basename "$H" .t.sol)
  # Find nearest foundry.toml ancestor of the harness OR nearest sibling.
  PROJ=""
  DIR=$(dirname "$H")
  while [ "$DIR" != "/" ] && [ -n "$DIR" ]; do
    if [ -f "$DIR/foundry.toml" ]; then
      PROJ="$DIR"; break
    fi
    DIR=$(dirname "$DIR")
  done
  # Fallback: nearest sibling of the workspace root.
  if [ -z "$PROJ" ]; then
    for D in "$WS" "$WS/src" "$WS/contracts"; do
      [ -f "$D/foundry.toml" ] && { PROJ="$D"; break; }
    done
  fi
  if [ -z "$PROJ" ]; then
    echo "| \`$STEM\` | - | NO-FOUNDRY-ROOT | no foundry.toml found anywhere above harness |" >> "$REPORT"
    continue
  fi

  LOG="$OUT_DIR/${STEM}_${TS}.log"
  ( cd "$PROJ" && \
    forge test --invariant-runs "$RUNS" --invariant-depth "$DEPTH" \
      --match-path "*${STEM}*" -vv ) > "$LOG" 2>&1
  RC=$?

  if [ "$RC" -eq 0 ]; then
    STATUS="PASS"
    NOTES="all invariants hold"
  else
    STATUS="BROKEN"
    # Grab the first [FAIL] or counterexample sequence for the note column
    NOTE=$(grep -E '\[FAIL|Test result: FAILED|invariant_.*:' "$LOG" | head -1 | tr '|' '/' | cut -c1-120)
    NOTES="${NOTE:-see $(basename "$LOG")}"
    FAILS=$((FAILS + 1))
  fi
  echo "| \`$STEM\` | \`${PROJ#$WS/}\` | $STATUS | $NOTES |" >> "$REPORT"
done

echo "" >> "$REPORT"
echo "Runs: $RUNS · Depth: $DEPTH · Harnesses: $(echo "$HARNESSES" | wc -l | tr -d ' ') · BROKEN: $FAILS" >> "$REPORT"

echo "[invariant-validate] wrote $REPORT"
echo "[invariant-validate] BROKEN harnesses: $FAILS"

[ "$FAILS" -gt 0 ] && exit 1 || exit 0
