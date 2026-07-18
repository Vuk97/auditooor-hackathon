#!/usr/bin/env bash
# init-asset-plan.sh — scaffold ASSET_PLAN_<Asset>.md template files from SCOPE.md
#
# Usage:
#   ./tools/init-asset-plan.sh <workspace-dir> [--force]
#
# Reads <workspace>/SCOPE.md to detect declared in-scope asset classes (typical
# labels: "Smart Contract", "Blockchain/DLT", "Web/App"). For each asset
# found, scaffolds <workspace>/ASSET_PLAN_<Asset_With_Underscores>.md with the
# exact key:value structure that tools/intake-baseline.py expects to parse:
#
#   # Asset Coverage Plan — <Asset>
#
#   - Strategy: TBD (operator: replace with concrete strategy)
#   - Estimated hours: 0
#   - Agent hour quota pct: 0
#   - Plan status: missing
#
#   ## Roots
#   - <bullet TBD>
#
# Refuses to overwrite an existing ASSET_PLAN_<...>.md unless --force is given
# (mirrors init-rubric-coverage.sh). Plan-status default is `missing` so that
# operators must explicitly promote to `ready` after filling in real values.
#
# Closes I-02 from PR #158: previously intake-baseline.py would hard-block on
# missing ASSET_PLAN files with no autofix, forcing operators to read source
# and hand-edit markdown to discover the required structure.

set -uo pipefail

if [ $# -lt 1 ]; then
    cat <<EOF
Usage: $0 <workspace-dir> [--force]

Reads <workspace-dir>/SCOPE.md to detect declared asset classes and scaffolds
<workspace-dir>/ASSET_PLAN_<Asset_With_Underscores>.md template files with the
exact structure tools/intake-baseline.py parses. Refuses to overwrite an
existing ASSET_PLAN file unless --force is given (existing plan content will
be lost).
EOF
    exit 1
fi

WS="$1"
FORCE=0
if [ "${2:-}" = "--force" ]; then
    FORCE=1
fi

if [ ! -d "$WS" ]; then
    echo "Error: workspace $WS not found"
    exit 1
fi

SCOPE="$WS/SCOPE.md"
if [ ! -f "$SCOPE" ]; then
    echo "Error: $SCOPE not found. Populate SCOPE.md before running this tool."
    exit 2
fi

# Asset-label detection. We scan SCOPE.md for the asset classes intake
# parser recognizes. Order is preserved:
#   Smart Contract → Blockchain/DLT → Web/App → Infrastructure
# A single asset is emitted at most once (de-duped).
# r36-rebuttal: lane gap-fix-ni-asset-plan-2026-05-28
# GAP-NI-3 fix: added "Infrastructure" detection. HackenProof scope tables
# label MPC / threshold-sig / off-chain backend repos as "Infrastructure";
# without this, init-asset-plan only emitted Smart_Contract for NEAR Intents,
# leaving the 2 critical Infrastructure repos uncovered in the asset gate.
detect_assets() {
    local scope_lower
    scope_lower=$(tr '[:upper:]' '[:lower:]' < "$SCOPE")
    local found=""
    if echo "$scope_lower" | grep -Eq 'smart[ -]contracts?'; then
        found="${found}Smart Contract
"
    fi
    if echo "$scope_lower" | grep -Eq 'blockchain[ /-]?dlt|blockchain / dlt'; then
        found="${found}Blockchain/DLT
"
    fi
    if echo "$scope_lower" | grep -Eq 'web[ /-]?app|websites?[ /]+\(?apps?\)?|web ?application'; then
        found="${found}Web/App
"
    fi
    if echo "$scope_lower" | grep -Eq 'infrastructure|backend|off-?chain|mpc network|threshold[ -]signature|relayer'; then
        found="${found}Infrastructure
"
    fi
    printf '%s' "$found"
}

# r36-rebuttal: lane gap-fix-ni-asset-plan-2026-05-28
# GAP-NI-4 fix: auto-fill Roots from targets.tsv + auto-fill Strategy from
# SCOPE.md program summary, so Plan status can default to "ready" instead of
# requiring manual TBD fill for every new workspace.
auto_roots_from_targets() {
    local targets_path="$WS/targets.tsv"
    if [ ! -f "$targets_path" ]; then
        echo "TBD (no targets.tsv yet; operator edit)"
        return
    fi
    # Parse col 3 (local_name) from each non-comment, non-blank line; emit
    # bullet "- src/<local_name>".
    awk -F'\t' '/^[^#]/ && NF >= 3 && $3 != "" { print "- src/" $3 }' "$targets_path" \
        | sort -u | head -20
}

auto_strategy_from_scope() {
    # Grab first non-header, non-blank paragraph after "## Program summary"
    # OR fallback to the first paragraph of the SCOPE.md body.
    local strategy
    strategy=$(awk '
        /^## Program summary/ { in_section=1; next }
        in_section && /^##/ { exit }
        in_section && NF > 0 && !/^- / && !/^#/ { print; exit }
    ' "$SCOPE" | head -1 | cut -c1-300)
    if [ -z "$strategy" ]; then
        # Fallback: first non-header line of the body
        strategy=$(awk 'NR > 5 && NF > 0 && !/^#/ && !/^-/ && !/^\*\*/ { print; exit }' "$SCOPE" | cut -c1-300)
    fi
    if [ -z "$strategy" ]; then
        echo "TBD (operator: derive from SCOPE.md program summary)"
    else
        echo "$strategy"
    fi
}

# Slug an asset label the same way intake-baseline.py's _asset_slug() does:
#   non-alnum runs become underscores, leading/trailing underscores stripped.
asset_slug() {
    printf '%s' "$1" | sed -e 's/[^A-Za-z0-9]\{1,\}/_/g' -e 's/^_//' -e 's/_$//'
}

ASSETS=$(detect_assets)
if [ -z "$ASSETS" ]; then
    echo "Error: no asset classes detected in $SCOPE."
    echo "Expected one or more of: 'Smart Contract', 'Blockchain/DLT', 'Web/App'."
    echo "Edit SCOPE.md to declare in-scope assets, then re-run."
    exit 2
fi

CREATED=0
SKIPPED=0
OVERWROTE=0

while IFS= read -r asset; do
    [ -z "$asset" ] && continue
    slug=$(asset_slug "$asset")
    out="$WS/ASSET_PLAN_${slug}.md"
    if [ -f "$out" ] && [ $FORCE -eq 0 ]; then
        echo "skip: $out already exists (pass --force to overwrite)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    existed=0
    [ -f "$out" ] && existed=1
    # r36-rebuttal: lane gap-fix-ni-asset-plan-2026-05-28
    # GAP-NI-4 fix: auto-fill from targets.tsv (Roots) + SCOPE.md (Strategy)
    # so Plan status defaults to "ready" when both sources have real data.
    auto_strategy=$(auto_strategy_from_scope)
    auto_roots=$(auto_roots_from_targets)
    if [[ "$auto_strategy" != TBD* ]] && [[ "$auto_roots" != TBD* ]] && [ -n "$auto_roots" ]; then
        plan_status="ready"
    else
        plan_status="missing"
    fi
    cat > "$out" <<EOF
# Asset Coverage Plan — $asset

- Strategy: $auto_strategy
- Estimated hours: 0
- Agent hour quota pct: 0
- Plan status: $plan_status

## Roots
$auto_roots
EOF
    if [ $existed -eq 1 ]; then
        echo "overwrote: $out"
        OVERWROTE=$((OVERWROTE + 1))
    else
        echo "created: $out"
        CREATED=$((CREATED + 1))
    fi
done <<EOF
$ASSETS
EOF

echo ""
echo "Summary: $CREATED created, $OVERWROTE overwritten, $SKIPPED skipped."
echo ""
echo "Next steps:"
echo "  1. Open each ASSET_PLAN_*.md in your editor."
echo "  2. Replace 'TBD' strategy + roots placeholders with concrete values."
echo "  3. Set realistic 'Estimated hours' and 'Agent hour quota pct'."
echo "  4. Promote 'Plan status: missing' → 'Plan status: ready' once filled."
echo "  5. Re-run tools/intake-baseline.py to confirm the asset-coverage gate clears."
