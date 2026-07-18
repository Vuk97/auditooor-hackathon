#!/usr/bin/env bash
# hexens-coverage-init.sh — generate a HEXENS_COVERAGE.md checklist for an audit workspace
#
# Usage:
#   ./tools/hexens-coverage-init.sh <workspace-dir>
#
# Creates <workspace-dir>/HEXENS_COVERAGE.md with all 152 Hexens Glider queries
# as checkbox rows. Each row can be marked PASS / N/A / FINDING / UNCHECKED as
# you work through the audit.
#
# Fixes Issue 6 from SKILL_ISSUES.md — durable per-query coverage tracking.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-dir>"
    echo "Creates <workspace-dir>/HEXENS_COVERAGE.md"
    exit 1
fi

WORKSPACE="$1"
AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
QUERIES_DIR="$AUDITOOOR_DIR/external/glider-query-db/queries"

if [ ! -d "$QUERIES_DIR" ]; then
    echo "Error: $QUERIES_DIR not found. Run 'make bootstrap' (preferred) or 'make init' to fetch submodules."
    exit 1
fi

if [ ! -d "$WORKSPACE" ]; then
    echo "Error: $WORKSPACE is not a directory"
    exit 1
fi

OUT="$WORKSPACE/HEXENS_COVERAGE.md"

cat > "$OUT" <<'HEADER'
# Hexens Glider Query Coverage

Durable checklist of all 152 Hexens detection queries. Update the verdict column as you work.

**Verdicts:**
- `⬜ UNCHECKED` — not yet looked at
- `✅ PASS` — verified clean in source
- `🚫 N/A` — not applicable to this target (e.g., DEX-specific query on a CLOB target)
- `⚠️ HITS` — grep found candidates, manual review needed
- `🎯 FINDING` — confirmed finding, see FINDINGS.md
- `📋 RE-EXAMINE` — closed conservatively, worth a second look

Each row references the query's Python source at `external/glider-query-db/queries/<file>.py`.

---

HEADER

echo "| # | Query | Verdict | Notes |" >> "$OUT"
echo "|---|---|---|---|" >> "$OUT"

i=0
for f in $(ls "$QUERIES_DIR"/*.py 2>/dev/null | sort); do
    i=$((i + 1))
    name=$(basename "$f" .py)
    printf "| %d | [\`%s\`](../../external/glider-query-db/queries/%s.py) | ⬜ UNCHECKED | |\n" \
        "$i" "$name" "$name" >> "$OUT"
done

cat >> "$OUT" <<'FOOTER'

---

## Usage

- Run `./tools/apply-queries.sh <src-dir>` from the auditooor directory for a quick automated sweep of ~50 common patterns.
- For queries not covered by `apply-queries.sh`, read the Python source directly and apply manually.
- Mark each row's verdict as you go. The running count at the bottom helps gauge coverage.

## Coverage stats

Run `./tools/coverage-report.sh <workspace>` to get a snapshot of how many rows are in each verdict state.
FOOTER

# Summary
total=$(ls "$QUERIES_DIR"/*.py 2>/dev/null | wc -l | tr -d ' ')
echo "Created: $OUT"
echo "Rows: $total"
