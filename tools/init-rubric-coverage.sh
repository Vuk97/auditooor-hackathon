#!/usr/bin/env bash
# init-rubric-coverage.sh — generate RUBRIC_COVERAGE.md from workspace severity rubric source(s)
#
# Usage:
#   ./tools/init-rubric-coverage.sh <workspace-dir> [--force]
#
# Parses the workspace's populated SEVERITY.md, or split
# SEVERITY_SMART_CONTRACTS.md + SEVERITY_BLOCKCHAIN_DLT.md files, for Critical /
# High / Medium / Low impact example bullets. Generates a per-example checklist
# in RUBRIC_COVERAGE.md with verdict column pre-filled as "📋 NOT CHECKED".
#
# Graceful termination (per methodology/iteration_workflow.md Phase 6) requires
# ≥90% rows in PASS / SUBMITTED / OOS / N/A state. PARTIAL and NOT CHECKED
# count as unresolved.
#
# Fixes SKILL_ISSUES.md #24 — skill had no mechanism to cross-reference iteration
# coverage against the bounty's own rubric-example list. Graceful termination at
# 71% rubric coverage (Polymarket iter 19) was recommended prematurely because
# the only yardstick being tracked was "zero-finding streak", not "rubric-example
# coverage".

set -uo pipefail

if [ $# -lt 1 ]; then
    cat <<EOF
Usage: $0 <workspace-dir> [--force]

Parses populated severity source files for rubric impact-example bullets and
generates <workspace-dir>/RUBRIC_COVERAGE.md as an editable per-example
checklist. Refuses to overwrite an existing file unless --force is given.
EOF
    exit 1
fi

WS="$1"
FORCE=0
if [ "${2:-}" = "--force" ]; then
    FORCE=1
fi

OUT="$WS/RUBRIC_COVERAGE.md"

if [ ! -d "$WS" ]; then
    echo "Error: workspace $WS not found"
    exit 1
fi

if [ -f "$OUT" ] && [ $FORCE -eq 0 ]; then
    echo "Error: $OUT already exists. Pass --force to overwrite (existing verdicts will be lost)."
    exit 1
fi

_is_placeholder_source() {
    # NOTE: match only TEMPLATE placeholders, not legit content. Immunefi's
    # 'Primacy of Impact asset placeholder' is real rubric terminology and must
    # NOT flag the file as an unfilled template.
    grep -Eiq 'TODO:|paste the bounty|<placeholder|\[placeholder|placeholder (text|here|below|for the)|copy from bounty platform|do not rely on memory' "$1"
}

SOURCE_FILES=""
for candidate in \
    "$WS/SEVERITY.md" \
    "$WS/SEVERITY_SMART_CONTRACTS.md" \
    "$WS/SEVERITY_BLOCKCHAIN_DLT.md" \
    "$WS/severity-rubric.md"
do
    if [ -f "$candidate" ] && ! _is_placeholder_source "$candidate"; then
        SOURCE_FILES="${SOURCE_FILES}${candidate}
"
    fi
done

if [ -z "$SOURCE_FILES" ]; then
    echo "Error: no populated severity rubric source found."
    echo "Paste the bounty rubric into SEVERITY.md, or split it into:"
    echo "  - SEVERITY_SMART_CONTRACTS.md"
    echo "  - SEVERITY_BLOCKCHAIN_DLT.md"
    echo "Then re-run this tool."
    exit 2
fi

# Extract impact-example bullets from the severity source files per tier. Looks
# for markdown sections labeled Critical / High / Medium / Low and their bullet
# lists.
# The bullets may be `- text` or `• text` or numbered `1. text` — normalize.
#
# We use awk to walk the file, track the current tier header, and accumulate
# bullet text under that tier. Bullets that span multiple lines are joined.

tmp=$(mktemp)
input=$(mktemp)
while IFS= read -r source; do
    [ -z "$source" ] && continue
    rel_source=${source#"$WS/"}
    {
        echo ""
        echo "# Source: $rel_source"
        cat "$source"
        echo ""
    } >> "$input"
done <<EOF
$SOURCE_FILES
EOF

awk '
    BEGIN {
        tier=""
        bullet=""
    }

    # Markdown TABLE row: | <tier> | <impact text> | ...  -> emit (tier, impact).
    # Many programs (incl. the Immunefi standard rubric) express the severity-to-
    # impact mapping as a table, not tier-header + bullets. Recognize a row whose
    # FIRST cell is exactly a tier name and emit its SECOND cell as the impact
    # example. Correctly ignores the column-header row (cell1="Severity"), the
    # |---|---| separator (cell1="---"), and Impact x Probability matrix rows
    # (cell1 is a probability label, not a bare tier).
    /^[ \t]*\|/ {
        n = split($0, _cells, "|")
        _c1 = _cells[2]; _c2 = _cells[3]
        gsub(/^[ \t]+/, "", _c1); gsub(/[ \t]+$/, "", _c1)
        gsub(/^[ \t]+/, "", _c2); gsub(/[ \t]+$/, "", _c2)
        _u = toupper(_c1)
        if ((_u=="CRITICAL" || _u=="HIGH" || _u=="MEDIUM" || _u=="LOW") && _c2 != "" && _c2 !~ /^-+$/) {
            if (bullet != "" && tier != "") { print tier "\t" bullet; bullet = "" }
            print _u "\t" _c2
        }
        next
    }

    # Tier header detection: match heading or bold line with exact tier name.
    # BSD awk does not support word boundaries, so use anchor+prefix matching.
    /^#+[ \t]*[Cc]ritical/ || /^\*\*[Cc]ritical/ {
        if (bullet != "" && tier != "") { print tier "\t" bullet }
        tier = "CRITICAL"; bullet = ""; next
    }
    /^#+[ \t]*[Hh]igh/ || /^\*\*[Hh]igh/ {
        if (bullet != "" && tier != "") { print tier "\t" bullet }
        tier = "HIGH"; bullet = ""; next
    }
    /^#+[ \t]*[Mm]edium/ || /^\*\*[Mm]edium/ {
        if (bullet != "" && tier != "") { print tier "\t" bullet }
        tier = "MEDIUM"; bullet = ""; next
    }
    /^#+[ \t]*[Ll]ow/ || /^\*\*[Ll]ow/ {
        if (bullet != "" && tier != "") { print tier "\t" bullet }
        tier = "LOW"; bullet = ""; next
    }

    # Bullet line start: `- ` or `* ` or numbered `1. `
    /^[ \t]*-[ \t]/ || /^[ \t]*\*[ \t]/ || /^[ \t]*[0-9]+\.[ \t]/ {
        if (bullet != "" && tier != "") { print tier "\t" bullet }
        sub(/^[ \t]*(-|\*|[0-9]+\.)[ \t]+/, "", $0)
        bullet = $0
        next
    }

    # Continuation line (indented plain text) — join to current bullet
    /^[ \t]+[^-*0-9]/ {
        if (bullet != "") {
            sub(/^[ \t]+/, " ", $0)
            bullet = bullet $0
        }
        next
    }

    # Blank line — flush
    /^[ \t]*$/ {
        if (bullet != "" && tier != "") { print tier "\t" bullet; bullet = "" }
        next
    }

    END {
        if (bullet != "" && tier != "") { print tier "\t" bullet }
    }
' "$input" > "$tmp"

# Count rows per tier
crit=$(awk -F'\t' '$1=="CRITICAL"' "$tmp" | wc -l | tr -d ' ')
hi=$(awk -F'\t' '$1=="HIGH"' "$tmp" | wc -l | tr -d ' ')
med=$(awk -F'\t' '$1=="MEDIUM"' "$tmp" | wc -l | tr -d ' ')
low=$(awk -F'\t' '$1=="LOW"' "$tmp" | wc -l | tr -d ' ')
total=$((crit + hi + med + low))

if [ "$total" -eq 0 ]; then
    echo "Error: no Critical/High/Medium/Low rubric impact examples parsed from populated source files."
    echo "Fix the severity source formatting instead of generating placeholder coverage."
    rm -f "$tmp" "$input"
    exit 2
fi

# Write the RUBRIC_COVERAGE.md header + per-tier tables
today=$(date -u +%Y-%m-%d)
wsname=$(basename "$WS")

cat > "$OUT" <<EOF
# Rubric Coverage — $wsname

Generated $today by \`tools/init-rubric-coverage.sh\`.

**Severity source files:**
EOF

while IFS= read -r source; do
    [ -z "$source" ] && continue
    rel_source=${source#"$WS/"}
    echo "- \`$rel_source\`" >> "$OUT"
done <<EOF
$SOURCE_FILES
EOF

cat >> "$OUT" <<EOF

Every row below maps ONE rubric impact example to an iter-level verdict. The
assistant is required to update each row as iterations clear the corresponding
class. Graceful termination requires ≥90% rows in PASS / SUBMITTED / OOS / N/A
state — PARTIAL and NOT CHECKED count as unresolved.

**Verdict legend:**

- ✅ PASS — explicitly cleared with agent verification + source citation
- 🚀 SUBMITTED — a bug in this exact class was found and submitted
- ⚠️ PARTIAL — touched but not with audit-level rigor; more work needed
- 🚫 OOS — out of scope per bounty exclusions
- ❌ N/A — rubric example doesn't apply (e.g., no governance in scope)
- 📋 NOT CHECKED — concrete gap, must be addressed before graceful termination

**Update protocol:** after every iteration that addresses any row, edit the
verdict column inline. At graceful-termination time, \`tools/coverage-report.sh\`
prints a summary; \`tools/pre-iter-check.sh\` soft-warns if >20% of rows are
still NOT CHECKED.

---

## Critical impact examples ($crit rows)

| # | Example | Verdict | Evidence / Gap |
|---|---|---|---|
EOF

i=0
awk -F'\t' '$1=="CRITICAL" {print $2}' "$tmp" | while IFS= read -r bullet; do
    i=$((i + 1))
    # Escape pipe chars in the bullet text for table compatibility
    clean=$(printf '%s' "$bullet" | sed 's/|/｜/g')
    echo "| C$i | $clean | 📋 NOT CHECKED | — |" >> "$OUT"
done

cat >> "$OUT" <<EOF

---

## High impact examples ($hi rows)

| # | Example | Verdict | Evidence / Gap |
|---|---|---|---|
EOF

i=0
awk -F'\t' '$1=="HIGH" {print $2}' "$tmp" | while IFS= read -r bullet; do
    i=$((i + 1))
    clean=$(printf '%s' "$bullet" | sed 's/|/｜/g')
    echo "| H$i | $clean | 📋 NOT CHECKED | — |" >> "$OUT"
done

cat >> "$OUT" <<EOF

---

## Medium impact examples ($med rows)

| # | Example | Verdict | Evidence / Gap |
|---|---|---|---|
EOF

i=0
awk -F'\t' '$1=="MEDIUM" {print $2}' "$tmp" | while IFS= read -r bullet; do
    i=$((i + 1))
    clean=$(printf '%s' "$bullet" | sed 's/|/｜/g')
    echo "| M$i | $clean | 📋 NOT CHECKED | — |" >> "$OUT"
done

cat >> "$OUT" <<EOF

---

## Low impact examples ($low rows)

| # | Example | Verdict | Evidence / Gap |
|---|---|---|---|
EOF

i=0
awk -F'\t' '$1=="LOW" {print $2}' "$tmp" | while IFS= read -r bullet; do
    i=$((i + 1))
    clean=$(printf '%s' "$bullet" | sed 's/|/｜/g')
    echo "| L$i | $clean | 📋 NOT CHECKED | — |" >> "$OUT"
done

cat >> "$OUT" <<EOF

---

## Coverage summary

| Tier | Total | ✅ PASS | 🚀 Submitted | ⚠️ Partial | 📋 Not checked | 🚫 OOS | ❌ N/A |
|---|---|---|---|---|---|---|---|
| Critical | $crit | 0 | 0 | 0 | $crit | 0 | 0 |
| High | $hi | 0 | 0 | 0 | $hi | 0 | 0 |
| Medium | $med | 0 | 0 | 0 | $med | 0 | 0 |
| Low | $low | 0 | 0 | 0 | $low | 0 | 0 |
| **TOTAL** | **$total** | **0** | **0** | **0** | **$total** | **0** | **0** |

**Resolution rate:** 0 / $total (0%). Graceful termination requires ≥90%.

*(Update this summary table as verdicts change. \`tools/coverage-report.sh\` will
parse the per-row verdicts and re-emit the summary automatically — but a
hand-maintained copy here lets you see the state without running the tool.)*
EOF

rm -f "$tmp" "$input"

echo "Created $OUT"
echo "Rubric rows: $total ($crit Critical + $hi High + $med Medium + $low Low)"
echo ""
echo "Next steps:"
echo "  1. Open $OUT in your editor."
echo "  2. For each row, pre-fill any verdicts that are ALREADY known from prior"
echo "     iterations (PASS / SUBMITTED / OOS / N/A)."
echo "  3. Use this file during every orient step to decide iter targets."
echo "  4. Update the verdict column inline as iterations clear rows."
