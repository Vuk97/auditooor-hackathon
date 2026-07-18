#!/usr/bin/env bash
# engagement-retro.sh — per-engagement retrospective (Issue #135).
#
# Rolls up what was learned during an audit into a single markdown file + auto-updates
# the skill's cross-engagement recurring-bug-families corpus.
#
# Usage:
#   ./tools/engagement-retro.sh <workspace>

set -u
STRICT=0
WS=""
for arg in "$@"; do
  case "$arg" in
    --strict) STRICT=1 ;;
    -h|--help) echo "usage: $0 [--strict] <workspace>"; exit 0 ;;
    *) WS="$arg" ;;
  esac
done
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 [--strict] <workspace>" >&2
  echo "  --strict   exit non-zero if RETROSPECTIVE.md still has unfilled ecosystem-lesson placeholders" >&2
  exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$WS/RETROSPECTIVE.md"
NAME=$(basename "$WS")
DATE=$(date -u +%Y-%m-%d)

# Issue #147: in --strict mode, do NOT clobber an existing RETROSPECTIVE.md
# (operator may have hand-edited the ecosystem-lesson section). Skip generation
# and jump straight to validation.
if [ "$STRICT" -eq 1 ] && [ -f "$OUT" ]; then
  echo "[retro][--strict] $OUT exists — validating only, not regenerating."
  RETRO_REGENERATED=0
else
  RETRO_REGENERATED=1

{
echo "# Retrospective — $NAME"
echo ""
echo "Generated: $DATE (auto by tools/engagement-retro.sh)."
echo ""
echo "---"
echo ""
echo "## Scan signal"

if [ -f "$WS/custom-detectors.log" ]; then
  echo ""
  echo '### Detectors fired (top 20)'
  echo ''
  echo '| # | Detector | Hits |'
  echo '|---|---|---:|'
  grep -oE '— [a-z0-9-]+:' "$WS/custom-detectors.log" 2>/dev/null \
    | sort | uniq -c | sort -rn | head -20 \
    | awk '{ sub(":", "", $0); count=$1; $1=""; det=$0; sub(/^[ \t]+/,"",det); sub(/^— /,"",det); printf "| %d | `%s` | %d |\n", NR, det, count }'
fi

if [ -f "$WS/FINDINGS.md" ]; then
  echo ''
  echo '### FINDINGS.md summary'
  echo ''
  DRAFT=$(grep -ciE '^\*\*Status:\*\*.*(DRAFT|draft)' "$WS/FINDINGS.md" 2>/dev/null | head -1)
  SUBMITTED=$(grep -ciE '(SUBMITTED|🚀)' "$WS/FINDINGS.md" 2>/dev/null | head -1)
  CLOSED=$(grep -ciE '(CLOSED|CLOSED-NOT-A-BUG|DUPE)' "$WS/FINDINGS.md" 2>/dev/null | head -1)
  echo "- DRAFT: ${DRAFT:-0}"
  echo "- SUBMITTED: ${SUBMITTED:-0}"
  echo "- CLOSED: ${CLOSED:-0}"
fi

if [ -d "$WS/agent_outputs" ]; then
  echo ''
  echo '### Agent outputs'
  echo ''
  COUNT=$(ls "$WS/agent_outputs/"*.md 2>/dev/null | wc -l | tr -d ' ')
  echo "- Total: $COUNT"
fi

if [ -d "$WS/prior_audits" ]; then
  DIGESTS=$(ls "$WS/prior_audits/DIGEST_"*.md 2>/dev/null | wc -l | tr -d ' ')
  echo ''
  echo "### Prior audits"
  echo ''
  echo "- $DIGESTS DIGEST_*.md files under prior_audits/"
fi

echo ''
echo '---'
echo ''
echo '## Lessons for the skill'
echo ''
echo '- [ ] Detector that over-fired:'
echo '- [ ] Detector that under-fired:'
echo '- [ ] New pattern class observed:'
echo '- [ ] Workflow friction:'
echo '- [ ] Tool gap:'
echo ''
echo '## Ecosystem lesson for recurring_bug_families.md'
echo ''
echo '- Name:'
echo "- Protocol: $NAME"
echo '- Why it recurs:'
echo '- Detector coverage: none / partial / full'
echo ''
echo '_After filling, re-run `./tools/digest-aggregate.sh` to refresh the corpus._'
} > "$OUT"

echo "[retro] wrote $OUT"

if [ -x "$AUDITOOOR_DIR/tools/digest-aggregate.sh" ]; then
  echo "[retro] refreshing cross-engagement corpus..."
  "$AUDITOOOR_DIR/tools/digest-aggregate.sh" 2>&1 | tail -3
fi
fi  # end of regeneration guard

# Issue #147: --strict enforces ecosystem-lesson placeholders are filled.
# A "blank" placeholder is one of:
#   "- Name:"                    (no value after the colon)
#   "- Why it recurs:"           (no value after the colon)
#   "- Detector coverage: none / partial / full"  (template literal unchanged)
if [ "$STRICT" -eq 1 ]; then
  MISSING=()
  if grep -qE '^- Name:[[:space:]]*$' "$OUT"; then MISSING+=("Name"); fi
  if grep -qE '^- Why it recurs:[[:space:]]*$' "$OUT"; then MISSING+=("Why it recurs"); fi
  if grep -qE '^- Detector coverage: none / partial / full[[:space:]]*$' "$OUT"; then MISSING+=("Detector coverage"); fi
  if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "[retro][--strict] FAIL: ecosystem-lesson fields still blank: ${MISSING[*]}" >&2
    echo "[retro][--strict] edit $OUT, fill the 'Ecosystem lesson' section, then re-run." >&2
    exit 1
  fi
  echo "[retro][--strict] OK: ecosystem-lesson fields filled."
fi
