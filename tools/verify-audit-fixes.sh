#!/usr/bin/env bash
# verify-audit-fixes.sh — R73 B4: check that audit-claimed fixes are actually
# present in the mainnet-deployed bytecode/source.
#
# Lesson from R69 Kiln V1: Spearbit audit said "setWithdrawer was REMOVED in
# fix d3a14f20". Manual grep on the Sourcify-downloaded mainnet impl showed
# setWithdrawer STILL PRESENT. The fix narrative was imprecise — what was
# actually removed was the sanction-oracle framework, not the setWithdrawer
# function itself. Without this tool, the drift was invisible until the R69
# cold-read caught it.
#
# Usage:
#   bash tools/verify-audit-fixes.sh <workspace> <audit-commit-sha>
#   bash tools/verify-audit-fixes.sh <workspace> --from-digest
#
# Flow:
#   1. Read the audit commit's patch (via `gh api` if repo has owner/name in
#      workspace's .auditooor-state.yaml, otherwise take a local diff file).
#   2. Extract from the patch:
#      - List of `-function X(...)` (claimed-removed functions)
#      - List of `-modifier M(...)` (claimed-removed modifiers)
#      - List of changed call-sites (every line with `-` that's a function call)
#   3. For each claimed-removed symbol, grep the workspace's canonical source
#      (src/kiln-canonical/src, src/snowbridge/contracts/src, etc.).
#   4. If a "removed" symbol still exists in mainnet source → AUDIT-FIX-DRIFT report.
#
# Output:
#   <workspace>/audit_fix_drift.md
#   Exit 0 if no drift found. Exit 2 if drift found.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat >&2 <<EOF
Usage:
  $0 <workspace> <audit-fix-commit-sha>
  $0 <workspace> --from-digest

Checks that functions / modifiers / state-vars the audit claims were
removed in the fix commit are actually absent from the mainnet-deployed
source (Sourcify-downloaded).

Examples:
  bash tools/verify-audit-fixes.sh ~/audits/kiln-v1 d3a14f20
  bash tools/verify-audit-fixes.sh ~/audits/kiln-v1 --from-digest
    (reads the "Fixed in commit XXX" markers out of prior_audits/DIGEST_*.md)
EOF
    exit 1
}

[ $# -lt 2 ] && usage

WS="$1"
TARGET="$2"

[ -d "$WS" ] || { echo "[err] workspace not found: $WS" >&2; exit 1; }

# ── Find canonical source dir under $WS ──
CANON_SRC=""
for candidate in "$WS/src"/*/src "$WS/src"/*/contracts/src "$WS/src"/*/contracts "$WS/src"/*/*/src "$WS/src"/src "$WS/src"; do
    if [ -d "$candidate" ] && ls "$candidate"/*.sol >/dev/null 2>&1; then
        CANON_SRC="$candidate"
        break
    fi
done
[ -z "$CANON_SRC" ] && { echo "[err] couldn't locate canonical Solidity source under $WS/src/" >&2; exit 1; }
echo "[verify-audit-fixes] canonical src: $CANON_SRC"

# ── Assemble list of (sha, fix-description) pairs to check ──
CHECKS=()  # each entry: "sha|description"

if [ "$TARGET" = "--from-digest" ]; then
    if ! ls "$WS"/prior_audits/DIGEST_*.md >/dev/null 2>&1; then
        echo "[err] --from-digest but no prior_audits/DIGEST_*.md found in $WS" >&2
        exit 1
    fi
    while IFS= read -r line; do
        # Match "Fixed in commit XXXXXXXX" or "Fixed in XXXXXXXX"
        sha=$(echo "$line" | grep -oE 'Fixed\s+(in\s+)?(commit\s+)?[a-f0-9]{7,40}' | grep -oE '[a-f0-9]{7,40}' | head -1)
        [ -z "$sha" ] && continue
        CHECKS+=("$sha|from-digest")
    done < <(grep -hE 'Fixed\s+(in\s+)?(commit\s+)?[a-f0-9]{7,40}' "$WS"/prior_audits/DIGEST_*.md 2>/dev/null)
    if [ ${#CHECKS[@]} -eq 0 ]; then
        echo "[info] no 'Fixed in commit' markers in DIGEST_*.md — nothing to verify"
        exit 0
    fi
    echo "[verify-audit-fixes] pulled ${#CHECKS[@]} fix-commit SHA(s) from DIGESTs"
else
    CHECKS+=("$TARGET|user-supplied")
fi

# ── Resolve repo owner/name from .auditooor-state.yaml or targets.tsv ──
REPO_OWNER=""
REPO_NAME=""
if [ -f "$WS/.auditooor-state.yaml" ]; then
    REPO_OWNER=$(grep -oE 'repo_owner:\s*\S+' "$WS/.auditooor-state.yaml" | awk '{print $NF}' | head -1)
    REPO_NAME=$(grep -oE 'repo_name:\s*\S+' "$WS/.auditooor-state.yaml" | awk '{print $NF}' | head -1)
fi
if [ -z "$REPO_OWNER" ] && [ -f "$WS/targets.tsv" ]; then
    URL=$(awk -F'\t' 'NR==1 {print $1}' "$WS/targets.tsv" 2>/dev/null | grep -oE 'https://github.com/[^/]+/[^/ ]+')
    if [ -n "$URL" ]; then
        REPO_OWNER=$(echo "$URL" | awk -F'/' '{print $4}')
        REPO_NAME=$(echo "$URL" | awk -F'/' '{print $5}')
    fi
fi

REPORT="$WS/audit_fix_drift.md"
rm -f "$REPORT"

{
    echo "# Audit-fix-vs-mainnet drift report"
    echo ""
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Workspace: $WS"
    echo "Canonical source: \`$CANON_SRC\`"
    [ -n "$REPO_OWNER" ] && echo "Repo: $REPO_OWNER/$REPO_NAME"
    echo ""
} >> "$REPORT"

drift_count=0

for check in "${CHECKS[@]}"; do
    sha="${check%%|*}"
    src="${check##*|}"
    echo "[verify-audit-fixes] checking commit $sha ..."
    {
        echo "## Fix commit \`$sha\` (source: $src)"
        echo ""
    } >> "$REPORT"

    patch_file=""
    if [ -n "$REPO_OWNER" ] && [ -n "$REPO_NAME" ] && command -v gh >/dev/null 2>&1; then
        # Try gh api
        patch_file="/tmp/audit-fix-${sha}.patch"
        gh api "repos/$REPO_OWNER/$REPO_NAME/commits/$sha" --jq '.files[] | select(.filename | endswith(".sol")) | "--- a/" + .filename + "\n+++ b/" + .filename + "\n" + .patch' > "$patch_file" 2>/dev/null
        if [ ! -s "$patch_file" ]; then
            patch_file=""
        fi
    fi

    if [ -z "$patch_file" ]; then
        echo "- [warn] could not fetch patch for $sha (no repo info / gh unavailable / 404). Skipping." >> "$REPORT"
        continue
    fi

    # Extract claimed-removed function names + modifier names from the patch
    removed_syms=$(awk '
        /^-\s*function\s+[a-zA-Z_][a-zA-Z0-9_]*/ {
            match($0, /function\s+([a-zA-Z_][a-zA-Z0-9_]*)/, arr); print "fn:" arr[1]
        }
        /^-\s*modifier\s+[a-zA-Z_][a-zA-Z0-9_]*/ {
            match($0, /modifier\s+([a-zA-Z_][a-zA-Z0-9_]*)/, arr); print "mod:" arr[1]
        }
    ' "$patch_file" 2>/dev/null | sort -u)

    if [ -z "$removed_syms" ]; then
        {
            echo "- [info] no function/modifier-level removals detected in patch."
            echo ""
        } >> "$REPORT"
        continue
    fi

    local_drift=0
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        kind="${entry%%:*}"
        name="${entry#*:}"
        # Grep canonical source for the symbol definition
        if [ "$kind" = "fn" ]; then
            hit=$(grep -rnE "^\s*function\s+${name}\s*\(" "$CANON_SRC" 2>/dev/null | head -3)
        else
            hit=$(grep -rnE "^\s*modifier\s+${name}\b" "$CANON_SRC" 2>/dev/null | head -3)
        fi
        if [ -n "$hit" ]; then
            drift_count=$((drift_count + 1))
            local_drift=$((local_drift + 1))
            {
                echo "- ❌ **DRIFT** — patch claims \`$kind $name\` removed but mainnet still has:"
                echo ""
                echo '  ```'
                echo "$hit" | sed 's/^/  /'
                echo '  ```'
            } >> "$REPORT"
        fi
    done <<< "$removed_syms"

    if [ $local_drift -eq 0 ]; then
        echo "- ✅ Patch-claimed removals are absent from mainnet source (consistent)." >> "$REPORT"
    fi
    echo "" >> "$REPORT"
done

{
    echo "## Summary"
    echo ""
    echo "- Fix commits checked: ${#CHECKS[@]}"
    echo "- Drift entries found: $drift_count"
    echo ""
    if [ $drift_count -gt 0 ]; then
        echo "**Action:** investigate each drift entry above. A drifted symbol is either:"
        echo "  1. The audit narrative was imprecise (the fix removed something else). Benign but confusing."
        echo "  2. Mainnet impl is older than the audit's fix commit. Potentially exploitable if the audit finding is real."
        echo "  3. The fix was partial — some occurrences left behind."
    else
        echo "No drift detected. All patch-claimed removals are absent from mainnet."
    fi
} >> "$REPORT"

echo ""
echo "[verify-audit-fixes] report: $REPORT"
echo "[verify-audit-fixes] drift entries: $drift_count"
[ $drift_count -gt 0 ] && exit 2
exit 0
