#!/usr/bin/env bash
# iter-dashboard.sh — one-screen status for an audit workspace (Issue #90).
#
# Prints: iter number / last-iter delta / Tier-S hits this iter / RUBRIC_COVERAGE %
# / zero-finding streak / DRAFT findings & dupe-risk / what pre-iter-check would block on.
#
# Usage: ./tools/iter-dashboard.sh <workspace-path>

set -u
WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <workspace-path>" >&2
  exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

print_section() {
  printf "\n\033[1m── %s ──\033[0m\n" "$1"
}

print_section "Workspace"
echo "  Path:    $WS"
echo "  Project: $(basename "$WS")"

print_section "Iteration state"
if [ -f "$WS/SESSION_LOG.md" ]; then
  LAST_ITER=$(grep -oE '^\| *[0-9]+ *\|' "$WS/SESSION_LOG.md" 2>/dev/null | tail -1 | tr -d '| ' || echo "0")
  LAST_ROW=$(grep -oE '^\| *[0-9]+ *\|.*' "$WS/SESSION_LOG.md" 2>/dev/null | tail -1 || echo "(no rows)")
  echo "  Last iter:    ${LAST_ITER:-0}"
  echo "  Last row:     ${LAST_ROW:0:120}"
else
  echo "  SESSION_LOG.md: MISSING"
fi

print_section "Findings"
if [ -f "$WS/FINDINGS.md" ]; then
  DRAFT=$(grep -ciE '^\*\*Status:\*\*.*(DRAFT|draft)' "$WS/FINDINGS.md" 2>/dev/null | head -1)
  SUBMITTED=$(grep -ciE '(SUBMITTED|🚀)' "$WS/FINDINGS.md" 2>/dev/null | head -1)
  CLOSED=$(grep -ciE '(CLOSED|CLOSED-NOT-A-BUG|DUPE)' "$WS/FINDINGS.md" 2>/dev/null | head -1)
  printf "  DRAFT:     %s\n  SUBMITTED: %s\n  CLOSED:    %s\n" "${DRAFT:-0}" "${SUBMITTED:-0}" "${CLOSED:-0}"
else
  echo "  FINDINGS.md: MISSING"
fi

print_section "Zero-finding streak"
if [ -f "$WS/SESSION_LOG.md" ]; then
  STREAK=0
  while IFS= read -r row; do
    DELTA=$(echo "$row" | awk -F'|' '{print $(NF-1)}' | tr -d ' ')
    if [ "$DELTA" = "0" ] || [ -z "$DELTA" ]; then
      STREAK=$((STREAK + 1))
    else
      break
    fi
  done < <(grep -E '^\| *[0-9]+ *\|' "$WS/SESSION_LOG.md" | awk '{a[NR]=$0}END{for(i=NR;i>=1;i--)print a[i]}')
  echo "  Current: $STREAK iterations"
  if [ "$STREAK" -ge 3 ]; then
    echo "  ⚠  Self-challenge mandatory (§3b) — list 3 alternative hypotheses not investigated."
  fi
fi

print_section "Rubric coverage"
if [ -f "$WS/RUBRIC_COVERAGE.md" ]; then
  TOTAL=$(grep -cE '^\| *[^|]+\|' "$WS/RUBRIC_COVERAGE.md" 2>/dev/null | head -1)
  RESOLVED=$(grep -cE '\| *(RESOLVED|CLEARED|CLOSED|SUBMITTED)' "$WS/RUBRIC_COVERAGE.md" 2>/dev/null | head -1)
  TOTAL=${TOTAL:-0}; RESOLVED=${RESOLVED:-0}
  if [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null; then
    PCT=$(( RESOLVED * 100 / TOTAL ))
    echo "  Resolved: $RESOLVED / $TOTAL ($PCT%)"
    [ "$PCT" -lt 90 ] && echo "  ⚠  Graceful termination blocked (need ≥90%)."
  fi
else
  echo "  RUBRIC_COVERAGE.md: MISSING"
fi

print_section "Pattern hits (from last scan)"
for f in "$WS/PATTERN_HITS.md" "$WS/SCAN_REPORT.md" "$WS/custom-detectors.log"; do
  if [ -f "$f" ]; then
    SIZE=$(wc -l < "$f" 2>/dev/null || echo 0)
    MTIME=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)
    echo "  $(basename "$f"): $SIZE lines (mtime: $MTIME)"
  fi
done

print_section "Dupe-risk on DRAFT findings"
if [ -d "$WS/drafts" ]; then
  for draft in "$WS"/drafts/*.md; do
    [ -f "$draft" ] || continue
    if [ -x "$AUDITOOOR_DIR/tools/dupe-risk.sh" ]; then
      RISK=$("$AUDITOOOR_DIR/tools/dupe-risk.sh" "$draft" 2>/dev/null | grep -iE "VERDICT:" | head -1 || echo "  (unknown)")
      echo "  $(basename "$draft"): $RISK"
    fi
  done
else
  echo "  (no drafts/ dir)"
fi

print_section "OOS overlap (per DRAFT)"
# Issue #130: per-DRAFT count of OOS-bullet keyword overlaps. Operator can spot
# at a glance which drafts are likely OOS dupes before submitting.
if [ -f "$WS/OOS_CHECKLIST.md" ] && [ -d "$WS/drafts" ]; then
  # Build keyword list from OOS bullets (one keyword per OOS-N line, drop short stopwords).
  TMP_OOS=$(mktemp -t oos_keywords.XXXXXX)
  trap 'rm -f "$TMP_OOS"' EXIT
  grep -oE '\*\*OOS-[0-9]+:\*\*[^$]*' "$WS/OOS_CHECKLIST.md" 2>/dev/null \
    | sed -E 's/\*\*OOS-[0-9]+:\*\*//' \
    | tr 'A-Z' 'a-z' \
    | tr -cs 'a-z0-9' '\n' \
    | awk 'length($0) >= 5' \
    | sort -u > "$TMP_OOS"
  KW_COUNT=$(wc -l < "$TMP_OOS" | tr -d ' ')
  if [ "$KW_COUNT" -eq 0 ]; then
    echo "  (OOS_CHECKLIST.md present but no keywords extracted)"
  else
    CLEAN=0; OVERLAP=0
    for draft in "$WS"/drafts/*.md; do
      [ -f "$draft" ] || continue
      HITS=$(tr 'A-Z' 'a-z' < "$draft" | grep -of "$TMP_OOS" 2>/dev/null | sort -u | wc -l | tr -d ' ')
      LABEL="clean"
      if [ "$HITS" -gt 0 ]; then OVERLAP=$((OVERLAP+1)); LABEL="$HITS OOS keyword(s) overlap"; else CLEAN=$((CLEAN+1)); fi
      printf "  %-45s %s\n" "$(basename "$draft")" "$LABEL"
    done
    echo "  ── totals: $OVERLAP overlapping with OOS, $CLEAN clean (keywords scanned: $KW_COUNT)"
  fi
elif [ ! -f "$WS/OOS_CHECKLIST.md" ]; then
  echo "  OOS_CHECKLIST.md: MISSING (run extract-oos.sh)"
else
  echo "  (no drafts/ dir)"
fi

print_section "Pre-iter gate check"
if [ -x "$AUDITOOOR_DIR/tools/pre-iter-check.sh" ]; then
  if "$AUDITOOOR_DIR/tools/pre-iter-check.sh" "$WS" >/dev/null 2>&1; then
    echo "  ✓ would allow next iter"
  else
    echo "  ✗ would HARD STOP — run pre-iter-check.sh $WS for details"
  fi
fi

# R37: cross-session memory (Issue #104)
if [ -f "$WS/.skill_state.yaml" ]; then
  print_section "Cross-session memory"
  LAST_SCAN=$(grep -E "^\s+date:" "$WS/.skill_state.yaml" 2>/dev/null | head -1 | awk '{print $2}' || echo "never")
  PENDING=$(grep -cE "^  - hypothesis:" "$WS/.skill_state.yaml" 2>/dev/null | head -1)
  READS=$(grep -cE "^  - contract:" "$WS/.skill_state.yaml" 2>/dev/null | head -1)
  printf "  Last scan:         %s\n" "${LAST_SCAN:-never}"
  printf "  Pending drills:    %s\n" "${PENDING:-0}"
  printf "  Adversarial reads: %s\n" "${READS:-0}"
  [ "${PENDING:-0}" -gt 0 ] 2>/dev/null && echo "  ⚠  Open drills — run: ./tools/skill-state.sh $WS drill-list"
fi

echo
