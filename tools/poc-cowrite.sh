#!/usr/bin/env bash
# poc-cowrite.sh — R73 A4: scaffold a Cantina-format PoC Foundry test from a
# DSL pattern + a workspace + a candidate target contract.
#
# The operator still writes the "concrete exploit" code — but everything
# around it (imports, forking setup, victim-attacker-treasury addresses,
# expected assertions, Cantina boilerplate) is generated from the pattern's
# class.
#
# Usage:
#   bash tools/poc-cowrite.sh <pattern-name> <workspace-dir> <target-contract>
#   bash tools/poc-cowrite.sh --list-classes
#
# Example:
#   bash tools/poc-cowrite.sh erc4626-redeem-passes-shares-to-underlying-pool \
#       ~/audits/some-vault-engagement \
#       src/vault/LoopVault.sol
#
# Output written to:
#   <workspace-dir>/test/poc/<pattern-name>.t.sol
#   <workspace-dir>/test/poc/<pattern-name>.cantina.md  (submission skeleton)
#
# The pattern-name is looked up in reference/patterns.dsl/<pattern-name>.yaml
# to pull severity / wiki_title / exploit_scenario / recommendation into the
# PoC comments and Cantina body.
#
# Template classes supported:
#   accounting-drift          — ERC4626 / vault share-price bugs
#   slippage-missing          — swap / redeem missing minOut
#   liquidation-inversion     — liquidate guard bug
#   pause-bypass              — paused wrapper + unpaused workhorse
#   oracle-stale              — price feed with stale round
#   role-elision              — role-check omission / dual-role bypass
#   cross-chain-lock-unlock   — bridge LOCK_UNLOCK conservation
#   reentrancy                — classic re-entrancy
#   arithmetic-underflow      — subtraction without clamp
#   init-reinit               — initializer replayable

set -euo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DSL_DIR="$AUDITOOOR_DIR/reference/patterns.dsl"
TPL_DIR="$AUDITOOOR_DIR/reference/poc_templates"

if [ "${1:-}" = "--list-classes" ]; then
    echo "Available PoC template classes:"
    ls "$TPL_DIR" 2>/dev/null | grep -E '\.t\.sol\.template$' | sed 's|\.t\.sol\.template$||; s|^|  |'
    exit 0
fi

[ $# -eq 3 ] || { echo "Usage: $0 <pattern-name> <workspace-dir> <target-contract>" >&2; exit 1; }
PATTERN="$1"; WS="$2"; TARGET="$3"

[ -d "$WS" ] || { echo "[err] workspace not found: $WS" >&2; exit 1; }

# ── Resolve DSL YAML ──
YAML="$DSL_DIR/$PATTERN.yaml"
if [ ! -f "$YAML" ]; then
    # Try mined staging dirs
    for cand in \
        "$AUDITOOOR_DIR/reference/patterns.dsl.r73_mined/code4rena/$PATTERN.yaml" \
        "$AUDITOOOR_DIR/reference/patterns.dsl.r73_mined/bridges/$PATTERN.yaml" \
        "$AUDITOOOR_DIR/reference/patterns.dsl.r73_mined/lst/$PATTERN.yaml" \
        "$AUDITOOOR_DIR/reference/patterns.dsl.r73_perps/$PATTERN.yaml"; do
        [ -f "$cand" ] && YAML="$cand" && break
    done
fi
[ -f "$YAML" ] || { echo "[err] pattern not found: $PATTERN" >&2; exit 1; }

# ── Extract metadata via python ──
META=$(python3 - "$YAML" <<'PY'
import yaml, sys, json
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
print(json.dumps({
    'severity': d.get('severity', 'UNKNOWN'),
    'wiki_title': d.get('wiki_title', ''),
    'wiki_description': d.get('wiki_description', ''),
    'wiki_exploit_scenario': d.get('wiki_exploit_scenario', ''),
    'wiki_recommendation': d.get('wiki_recommendation', ''),
    'help': d.get('help', ''),
    'pattern': d.get('pattern', ''),
}))
PY
)

SEVERITY=$(echo "$META" | python3 -c "import json,sys; print(json.load(sys.stdin)['severity'])")
TITLE=$(echo "$META" | python3 -c "import json,sys; print(json.load(sys.stdin)['wiki_title'])")
SCENARIO=$(echo "$META" | python3 -c "import json,sys; print(json.load(sys.stdin)['wiki_exploit_scenario'])")
RECO=$(echo "$META" | python3 -c "import json,sys; print(json.load(sys.stdin)['wiki_recommendation'])")

# ── Pick template class via keyword match on pattern name ──
pick_class() {
    local p="$1" n; n=$(echo "$p" | tr '[:upper:]' '[:lower:]')
    case "$n" in
        *erc4626*|*vault*share*|*redeem*pool*|*share*rate*|*accounting*)  echo "accounting-drift" ;;
        *slippage*|*minout*|*minamount*|*swap*slippage*)                    echo "slippage-missing" ;;
        *liquidat*guard*|*liquidation*inverted*|*margin*)                   echo "liquidation-inversion" ;;
        *pause*bypass*|*whenpaused*)                                        echo "pause-bypass" ;;
        *oracle*stale*|*sequencer*|*pricefeed*)                             echo "oracle-stale" ;;
        *role*|*whitelist*|*blacklist*)                                     echo "role-elision" ;;
        *bridge*|*lock*unlock*|*cross*chain*)                               echo "cross-chain-lock-unlock" ;;
        *reentra*|*callback*|*externalcall*)                                echo "reentrancy" ;;
        *underflow*|*overflow*|*subtract*)                                  echo "arithmetic-underflow" ;;
        *initiali*|*reinit*|*cloneinit*)                                    echo "init-reinit" ;;
        *)                                                                  echo "generic" ;;
    esac
}
CLASS=$(pick_class "$PATTERN")
TPL="$TPL_DIR/$CLASS.t.sol.template"
[ -f "$TPL" ] || TPL="$TPL_DIR/generic.t.sol.template"
[ -f "$TPL" ] || { echo "[err] no template found (even generic)" >&2; exit 1; }

# ── Output paths ──
OUT_SOL="$WS/test/poc/${PATTERN}.t.sol"
OUT_MD="$WS/test/poc/${PATTERN}.cantina.md"
mkdir -p "$WS/test/poc"

# ── Render template ──
CONTRACT_NAME=$(basename "$TARGET" .sol)
PATTERN_CAMEL=$(echo "$PATTERN" | awk -F'-' '{for(i=1;i<=NF;i++) printf "%s", toupper(substr($i,1,1)) substr($i,2); print ""}')

sed \
    -e "s|__PATTERN__|$PATTERN|g" \
    -e "s|__PATTERN_CAMEL__|$PATTERN_CAMEL|g" \
    -e "s|__TARGET_PATH__|$TARGET|g" \
    -e "s|__TARGET_CONTRACT__|$CONTRACT_NAME|g" \
    -e "s|__SEVERITY__|$SEVERITY|g" \
    "$TPL" > "$OUT_SOL"

# ── Render Cantina submission skeleton ──
cat > "$OUT_MD" <<EOF
# $TITLE

**Severity:** $SEVERITY
**Category:** (Bug / Economic / DoS / Access Control — operator picks)
**Protocol:** (workspace name)
**Commit:** (pinned SHA from target)

## Summary

(One-sentence summary of the bug. Auto-filled from pattern.help — rewrite
in your own voice before submitting.)

## Finding description

$SCENARIO

## Impact

(Quantify: worst-case loss per action, scale across actors/time/assets.)

## Proof of concept

See \`test/poc/${PATTERN}.t.sol\`. Run with:

\`\`\`bash
forge test --match-test "test_${PATTERN_CAMEL}_*" -vvv \\
    --fork-url \$ETH_RPC_URL --fork-block-number <pinned>
\`\`\`

Expected output: …

## Recommended mitigation

$RECO

## References

- Detector pattern: \`reference/patterns.dsl/${PATTERN}.yaml\`
- Upstream audit note (if any): TBD
EOF

echo "[ok] wrote PoC scaffold  : $OUT_SOL"
echo "[ok] wrote Cantina draft : $OUT_MD"
echo "[ok] template class used : $CLASS"
echo ""
echo "Next steps:"
echo "  1. Fill in the concrete exploit in $OUT_SOL"
echo "  2. Replace TBD fields in $OUT_MD"
echo "  3. Run: pre-submit-check.sh $WS $OUT_MD"
