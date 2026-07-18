#!/usr/bin/env bash
# economic-hypotheses-ir.sh — shim for the Python IR-based tool.
#
# R89 gap G3 fix: auto-discover sub-projects when invoked on a workspace-root
# with multiple foundry.toml / hardhat.config.js files (e.g. Morpho: 13 sub-repos,
# Polymarket: v1 + v2 trees). The Python tool below expects a SINGLE Foundry/
# Hardhat project or a single .sol file. If the caller hands us a workspace
# root, we run it once per sub-project and aggregate the output.
#
# Usage:
#   ./tools/economic-hypotheses-ir.sh <contract.sol|project-dir>  [--only 1,2,...]
#
# Multi-project mode triggers when:
#   - target is a directory AND
#   - NO `foundry.toml`/`hardhat.config.js` at target root AND
#   - >=1 sub-directory containing foundry.toml/hardhat.config.js
# In that case:
#   - run the Python tool per sub-project
#   - aggregate all violations into <workspace>/economic_hypotheses.md
#   - exit 0 if >=1 sub-project succeeded, else exit 3
#
# Exit codes:
#   0  success (single-project mode or >=1 sub-project succeeded)
#   2  usage error
#   3  all sub-projects failed (or single-project compile failed)

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"

find_python_with_slither() {
    if [ -n "${AUDITOOOR_PYTHON_SLITHER:-}" ]; then
        if "$AUDITOOOR_PYTHON_SLITHER" -c 'import slither' >/dev/null 2>&1; then
            printf '%s\n' "$AUDITOOOR_PYTHON_SLITHER"
            return 0
        fi
        echo "[warn] AUDITOOOR_PYTHON_SLITHER=$AUDITOOOR_PYTHON_SLITHER cannot import slither" >&2
    fi
    for py in python3 python3.14 python3.13 python3.12 python3.11 python; do
        if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import slither' >/dev/null 2>&1; then
            command -v "$py"
            return 0
        fi
    done
    return 1
}

PYTHON_SLITHER_BIN="$(find_python_with_slither || true)"
if [ -z "$PYTHON_SLITHER_BIN" ]; then
    echo "[err] no Python interpreter on PATH can import slither. Set AUDITOOOR_PYTHON_SLITHER=/path/to/python or install slither-analyzer for python3." >&2
    exit 3
fi

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <contract.sol|project-dir> [--only 1,2,...]" >&2
    exit 2
fi

TARGET="$1"
shift

# Single-file mode -> forward as-is
if [ -f "$TARGET" ]; then
    exec "$PYTHON_SLITHER_BIN" "$HERE/economic-hypotheses-ir.py" "$TARGET" "$@"
fi

if [ ! -d "$TARGET" ]; then
    echo "[err] target not found: $TARGET" >&2
    exit 2
fi

# Single-project: target itself has foundry.toml / hardhat.config.*
if [ -f "$TARGET/foundry.toml" ] || [ -f "$TARGET/hardhat.config.js" ] || [ -f "$TARGET/hardhat.config.ts" ]; then
    exec "$PYTHON_SLITHER_BIN" "$HERE/economic-hypotheses-ir.py" "$TARGET" "$@"
fi

# Multi-project: auto-discover sub-projects (excluding dependency lib/ dirs)
SUB_PROJECTS=()
while IFS= read -r toml; do
    SUB_PROJECTS+=("$(dirname "$toml")")
done < <(find "$TARGET" -maxdepth 4 -name "foundry.toml" -not -path "*/lib/*" -not -path "*/node_modules/*" 2>/dev/null | sort -u)

if [ "${#SUB_PROJECTS[@]}" -eq 0 ]; then
    echo "[err] no foundry.toml / hardhat.config.* found in $TARGET" >&2
    exit 3
fi

echo "[multi] $TARGET contains ${#SUB_PROJECTS[@]} sub-project(s)"

AGG_MD="$TARGET/economic_hypotheses.md"
{
    echo "# Economic hypotheses IR scan (multi-sub-project aggregate)"
    echo ""
    echo "Run via \`tools/economic-hypotheses-ir.sh\` on \`$TARGET\` at $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo ""
    echo "Sub-projects discovered: ${#SUB_PROJECTS[@]}"
    echo ""
    echo "| Sub-project | Status | Violations |"
    echo "|---|---|---|"
} > "$AGG_MD"

OK=0
FAIL=0
for proj in "${SUB_PROJECTS[@]}"; do
    proj_name="${proj#$TARGET/}"
    echo "[multi] scanning: $proj_name"
    tmp_out="$(mktemp -t econ-ir.XXXXXX)"
    if "$PYTHON_SLITHER_BIN" "$HERE/economic-hypotheses-ir.py" "$proj" --out "$tmp_out" "$@" >/dev/null 2>&1 && [ -s "$tmp_out" ]; then
        OK=$((OK + 1))
        vios=$(grep -cE '^- \[' "$tmp_out" 2>/dev/null | head -1 || echo 0)
        echo "| \`$proj_name\` | OK | $vios |" >> "$AGG_MD"
        {
            echo ""
            echo "## \`$proj_name\`"
            echo ""
            cat "$tmp_out"
        } >> "$AGG_MD"
    else
        FAIL=$((FAIL + 1))
        echo "| \`$proj_name\` | FAIL | — |" >> "$AGG_MD"
    fi
    rm -f "$tmp_out"
done

echo "" >> "$AGG_MD"
echo "**Totals: $OK OK, $FAIL FAIL**" >> "$AGG_MD"

echo "[multi] done. $OK OK, $FAIL FAIL"
echo "[multi] aggregate: $AGG_MD"

if [ "$OK" -ge 1 ]; then
    exit 0
fi
exit 3
