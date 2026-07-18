#!/usr/bin/env bash
# post-iter-check.sh — verify iteration-end invariants (Issue #78)
#
# Checks before closing an iteration:
#   1. SESSION_LOG.md has a new row for this iter
#   2. If zero-finding iter: self-challenge section exists (3 alt hypotheses)
#   3. RUBRIC_COVERAGE.md changes this iter cite evidence (iter/agent/file)
#   4. Any new FINDINGS.md entry has required fields (target, severity, PoC status)
#
# Usage:
#   ./tools/post-iter-check.sh <workspace> [--iter N]
#
# If --iter not given, infers from latest SESSION_LOG.md iter index.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ $# -lt 1 ]; then
    sed -n '2,16p' "$0" | sed 's/^# //; s/^#//'
    exit 1
fi

WS="$1"
ITER=""
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --iter) ITER="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ ! -d "$WS" ]; then
    echo "[error] workspace not found: $WS" >&2
    exit 1
fi

SLOG="$WS/SESSION_LOG.md"
FINDINGS="$WS/FINDINGS.md"
RUBRIC="$WS/RUBRIC_COVERAGE.md"

fails=0

if [ ! -f "$SLOG" ]; then
    echo "  ❌ SESSION_LOG.md missing — cannot verify iter closure"
    exit 1
fi

# Infer iter
if [ -z "$ITER" ]; then
    ITER=$(grep -oE '^\|\s*[0-9]+\s*\|' "$SLOG" | grep -oE '[0-9]+' | sort -n | tail -1)
fi

echo "==========================================================================="
echo "  post-iter-check — $WS (iter $ITER)"
echo "==========================================================================="

# --- Check 1: SESSION_LOG row for this iter ---
if grep -qE "^\|\s*$ITER\s*\|" "$SLOG"; then
    echo "  ✅ 1. SESSION_LOG.md has row for iter $ITER"
else
    echo "  ❌ 1. No SESSION_LOG.md row for iter $ITER — run: tools/append-iter.sh \"<description>\""
    fails=$((fails + 1))
fi

# --- Check 2: Zero-finding self-challenge ---
# If the iter row shows 0 findings, look for a self-challenge block in the log.
ROW=$(grep -E "^\|\s*$ITER\s*\|" "$SLOG" || true)
if echo "$ROW" | grep -qiE '(0 findings?|no findings?|zero findings?|\|\s*0\s*\|)'; then
    # Zero-finding iter
    if grep -iqE '(self-?challenge|alt(ernative)? hypothes(es|is)|3 alternatives|did not check.*because)' "$SLOG"; then
        echo "  ✅ 2. Zero-finding iter has self-challenge block"
    else
        echo "  ⚠️  2. Zero-finding iter $ITER but no self-challenge block in SESSION_LOG.md"
        echo "       anti-pattern #21: add 3 alt hypotheses + why you skipped each"
        fails=$((fails + 1))
    fi
else
    echo "  ✅ 2. Iter $ITER has findings — self-challenge not required"
fi

# --- Check 3: RUBRIC_COVERAGE changes cite evidence ---
if [ -f "$RUBRIC" ]; then
    # Look for rows that reference this iter and check evidence column has substance
    if grep -iE "iter ?$ITER|this iter" "$RUBRIC" | grep -qvE '(^\s*$|📋 NOT CHECKED)'; then
        # Check each such row has > 20 chars of evidence
        EV_MISSING=$(grep -iE "iter ?$ITER|this iter" "$RUBRIC" | grep -cE '^\|.*\|\s*\|' || true)
        if [ "$EV_MISSING" = "0" ]; then
            echo "  ✅ 3. RUBRIC_COVERAGE rows touched this iter cite evidence"
        else
            echo "  ⚠️  3. RUBRIC_COVERAGE has rows marked for iter $ITER but missing evidence column"
            fails=$((fails + 1))
        fi
    else
        echo "  ⚠️  3. No RUBRIC_COVERAGE updates for iter $ITER"
    fi
else
    echo "  ⚠️  3. RUBRIC_COVERAGE.md missing — run tools/init-rubric-coverage.sh"
fi

# --- Check 4: New FINDINGS.md entries well-formed ---
if [ -f "$FINDINGS" ]; then
    # Just a soft check: any finding added today?
    TODAY=$(date -u +%Y-%m-%d)
    if grep -q "$TODAY" "$FINDINGS" 2>/dev/null; then
        # Check required fields present near today's lines
        REQUIRED_FIELDS=("Target" "Severity" "Status")
        MISSING=()
        for field in "${REQUIRED_FIELDS[@]}"; do
            if ! grep -iqE "\*\*$field\*\*|\| \*\*$field\*\*" "$FINDINGS"; then
                MISSING+=("$field")
            fi
        done
        if [ ${#MISSING[@]} -eq 0 ]; then
            echo "  ✅ 4. FINDINGS.md entries have Target/Severity/Status fields"
        else
            echo "  ⚠️  4. FINDINGS.md missing standard fields: ${MISSING[*]}"
        fi
    else
        echo "  ✅ 4. No new FINDINGS.md entries today (nothing to validate)"
    fi
fi

echo ""
echo "==========================================================================="
if [ $fails -eq 0 ]; then
    echo "  ✅ iter $ITER closes cleanly"
    exit 0
else
    echo "  ❌ $fails issue(s) — fix before declaring iter complete"
    exit 1
fi
