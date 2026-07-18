#!/usr/bin/env bash
# scan.sh — unified scan orchestrator for auditooor workspaces
#
# Usage:
#   ./tools/scan.sh <workspace-dir> [--type exchange|lending|vault|bridge|dex|bundler]
#
# Infers target type from AUDIT.md/SCOPE.md if not specified.
# Runs the right scans in the right order with the right filters:
#
#   1. apply-queries.sh      — Hexens 152 query grep approximations (fast, ~2s)
#   2. apply-patterns.sh     — bug_patterns_observed + solodit_grep_catalog (fast, ~5s)
#   3. run-slither.sh        — Slither + Aderyn + Semgrep baseline (slow, ~30s)
#   4. solodit-cross-ref.sh  — Solodit API search plan by target type (fast, ~1s)
#   5. generate-hypotheses.sh — scan-first hypothesis prompt (fast, ~1s)
#
# Produces:
#   <workspace>/SCAN_REPORT.md — unified triage of all scan results
#
# Fixes SKILL_ISSUES.md #73.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ $# -lt 1 ]; then
    cat >&2 <<'USAGE'
Usage: ./tools/scan.sh <workspace-dir> [--type exchange|lending|vault|bridge|dex|bundler]

Runs all mechanical scans against the workspace source with target-type
filtering. Infers target type from AUDIT.md/SCOPE.md if --type is omitted.
USAGE
    exit 1
fi

WS="$1"
TARGET_TYPE=""
FORCE_STATIC=0
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --type) TARGET_TYPE="$2"; shift 2 ;;
        --force-static) FORCE_STATIC=1; shift ;;
        *) shift ;;
    esac
done

if [ ! -d "$WS" ]; then
    echo "[error] workspace not found: $WS" >&2
    exit 1
fi

# ---- Infer target type from workspace metadata ----
# R49 Bug 2 fix: autodetect can return a comma-separated list (strongest + any
# secondary). Hybrid protocols like Centrifuge (vault + exchange + bridge) no
# longer fall through to `general`. Operator can also pass --type as a comma
# list manually (e.g. --type vault,bridge).
if [ -z "$TARGET_TYPE" ]; then
    # Score each candidate type by pattern-match count across metadata.
    declare -a T_NAMES=(exchange lending vault bridge dex bundler)
    declare -a T_SCORES=(0 0 0 0 0 0)
    for f in "$WS/AUDIT.md" "$WS/SCOPE.md" "$WS/scope.json"; do
        [ -f "$f" ] || continue
        content=$(head -200 "$f" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        T_SCORES[0]=$(( T_SCORES[0] + $(echo "$content" | grep -cE 'exchange|clob|order.?book|matching.?engine|trading' || true) ))
        T_SCORES[1]=$(( T_SCORES[1] + $(echo "$content" | grep -cE 'lending|borrow|collateral.?factor|liquidat|interest.?rate|ltv' || true) ))
        T_SCORES[2]=$(( T_SCORES[2] + $(echo "$content" | grep -cE 'vault|erc4626|deposit.*shares|withdraw.*assets|yield' || true) ))
        T_SCORES[3]=$(( T_SCORES[3] + $(echo "$content" | grep -cE 'bridge|cross.?chain|relay|message.?pass|layerzero|wormhole' || true) ))
        T_SCORES[4]=$(( T_SCORES[4] + $(echo "$content" | grep -cE 'amm|swap|pool|liquidity|uniswap|curve|balancer' || true) ))
        T_SCORES[5]=$(( T_SCORES[5] + $(echo "$content" | grep -cE 'bundler|multicall|batch|meta.?transaction|relayer' || true) ))
    done
    # Pick the strongest + any secondaries with ≥ 25% of the top score (min 2 hits).
    max=0
    for s in "${T_SCORES[@]}"; do
        [ "$s" -gt "$max" ] && max="$s"
    done
    if [ "$max" -gt 0 ]; then
        # Strongest first.
        for i in 0 1 2 3 4 5; do
            if [ "${T_SCORES[$i]}" = "$max" ]; then
                TARGET_TYPE="${T_NAMES[$i]}"
                break
            fi
        done
        # Threshold for "also counts": max/4 or 2, whichever is larger.
        thresh=$(( max / 4 )); [ "$thresh" -lt 2 ] && thresh=2
        PRIMARY_NAME="$TARGET_TYPE"
        for i in 0 1 2 3 4 5; do
            [ "${T_NAMES[$i]}" = "$PRIMARY_NAME" ] && continue
            if [ "${T_SCORES[$i]}" -ge "$thresh" ]; then
                TARGET_TYPE="$TARGET_TYPE,${T_NAMES[$i]}"
            fi
        done
        unset PRIMARY_NAME
    fi
    if [ -z "$TARGET_TYPE" ]; then
        TARGET_TYPE="general"
        echo "[warn] could not infer target type — defaulting to 'general'" >&2
    fi
fi

# Dedup TARGET_TYPE (keep first occurrence of each unique type, preserve order).
if [[ "$TARGET_TYPE" == *,* ]]; then
    TARGET_TYPE=$(echo "$TARGET_TYPE" | awk -F',' '{
        seen=""; out=""
        for (i=1;i<=NF;i++) {
            t=$i; gsub(/[[:space:]]/,"",t)
            if (t=="" || index(seen, " "t" ")) continue
            seen = seen" "t" "
            out = (out=="") ? t : out","t
        }
        print out
    }')
fi

# Split comma list → primary + secondaries for per-scan targeting.
PRIMARY_TYPE="${TARGET_TYPE%%,*}"
SECONDARY_TYPES=""
if [[ "$TARGET_TYPE" == *,* ]]; then
    SECONDARY_TYPES="${TARGET_TYPE#*,}"
fi

echo "============================================================================"
echo "  auditooor scan — $WS"
echo "  Target type: $TARGET_TYPE"
echo "============================================================================"
echo ""

# Find source directory
SRC_DIR=""
for candidate in "$WS/src" "$WS/contracts" "$WS"; do
    if [ -d "$candidate" ]; then
        sol_found=$(find "$candidate" -name "*.sol" -not -path "*/test/*" -not -path "*/lib/*" -print -quit 2>/dev/null)
        if [ -n "$sol_found" ]; then
            SRC_DIR="$candidate"
            break
        fi
    fi
done

if [ -z "$SRC_DIR" ]; then
    RUST_FOUND=$(find "$WS" -name "*.rs" \
        -not -path "*/target/*" \
        -not -path "*/tests/*" \
        -not -path "*/fuzz/*" \
        -print -quit 2>/dev/null)
    if [ -n "$RUST_FOUND" ]; then
        RUST_COUNT=$(find "$WS" -name "*.rs" \
            -not -path "*/target/*" \
            -not -path "*/tests/*" \
            -not -path "*/fuzz/*" 2>/dev/null | wc -l | tr -d ' ')
        REPORT="$WS/SCAN_REPORT.md"
        cat > "$REPORT" <<HEADER
# Scan Report — $(basename "$WS")

**Target type:** $TARGET_TYPE
**Source:** Rust-only workspace ($RUST_COUNT .rs files)
**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

---

The broad Solidity scan facade skipped because no Solidity source was found.
Rust/Soroban detector results are produced by \`scan-rust\` in:

- \`scanners/rust/SCAN_RUST_SUMMARY.md\`
- \`scanners/rust/SCAN_RUST_SUMMARY.json\`
- \`.auditooor/rust_source_graph.json\`
- \`.auditooor/rust_cross_crate_graph.json\`

HEADER
        echo "[warn] No Solidity source found; wrote Rust-only scan facade report to $REPORT" >&2
        exit 0
    fi
    CIRCOM_FOUND=$(find "$WS" -name "*.circom" \
        -not -path "*/node_modules/*" \
        -not -path "*/lib/*" \
        -not -path "*/test/*" \
        -not -path "*/tests/*" \
        -print -quit 2>/dev/null)
    if [ -n "$CIRCOM_FOUND" ]; then
        CIRCOM_COUNT=$(find "$WS" -name "*.circom" \
            -not -path "*/node_modules/*" \
            -not -path "*/lib/*" \
            -not -path "*/test/*" \
            -not -path "*/tests/*" 2>/dev/null | wc -l | tr -d ' ')
        REPORT="$WS/SCAN_REPORT.md"
        cat > "$REPORT" <<HEADER
# Scan Report — $(basename "$WS")

**Target type:** $TARGET_TYPE
**Source:** Circom-only workspace ($CIRCOM_COUNT .circom files)
**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

---

The broad Solidity scan facade skipped because no Solidity source was found.
Circom detector results are produced by \`workspace-scan-orchestrator.py\` in
\`circom-detect.log\` and the parseable \`scan_report.md\`.

HEADER
        echo "[warn] No Solidity source found; wrote Circom-only scan facade report to $REPORT" >&2
        exit 0
    fi
    GO_FOUND=$(find "$WS" -name "*.go" \
        -not -path "*/.git/*" \
        -not -path "*/.auditooor/*" \
        -not -path "*/vendor/*" \
        -not -path "*/third_party/*" \
        -not -path "*/testdata/*" \
        -not -path "*/test/*" \
        -not -path "*/tests/*" \
        -print -quit 2>/dev/null)
    if [ -n "$GO_FOUND" ]; then
        GO_COUNT=$(find "$WS" -name "*.go" \
            -not -path "*/.git/*" \
            -not -path "*/.auditooor/*" \
            -not -path "*/vendor/*" \
            -not -path "*/third_party/*" \
            -not -path "*/testdata/*" \
            -not -path "*/test/*" \
            -not -path "*/tests/*" 2>/dev/null | wc -l | tr -d ' ')
        REPORT="$WS/SCAN_REPORT.md"
        cat > "$REPORT" <<HEADER
# Scan Report — $(basename "$WS")

**Target type:** $TARGET_TYPE
**Source:** Go/Cosmos workspace ($GO_COUNT .go files)
**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

---

The broad Solidity scan facade skipped because no Solidity source was found.
Go/Cosmos detector results are produced by \`workspace-scan-orchestrator.py\` in
\`cosmos_findings.json\` and the parseable \`scan_report.md\`.

HEADER
        echo "[warn] No Solidity source found; wrote Go/Cosmos scan facade report to $REPORT" >&2
        exit 0
    fi
    echo "[error] No Solidity source found in $WS" >&2
    exit 1
fi

SOL_COUNT=$(find "$SRC_DIR" -name "*.sol" -not -path "*/test/*" -not -path "*/lib/*" 2>/dev/null | wc -l | tr -d ' ')
echo "  Source: $SRC_DIR ($SOL_COUNT .sol files)"
echo ""

REPORT="$WS/SCAN_REPORT.md"
cat > "$REPORT" <<HEADER
# Scan Report — $(basename "$WS")

**Target type:** $TARGET_TYPE
**Source:** $SRC_DIR ($SOL_COUNT .sol files)
**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

---

HEADER

SCAN_RESULTS=()

# ---- Static-analysis dispatch helpers ----
# Prefer the profile-aware multisolc detector path only when the workspace
# shape clearly needs it. This keeps simple repos on the cheaper default path
# while giving mixed-pragma / multi-profile layouts better custom-detector
# coverage.
count_distinct_pragmas() {
    local tmp
    tmp=$(mktemp)
    while IFS= read -r -d '' sol; do
        grep -h -m1 -E 'pragma[[:space:]]+solidity[[:space:]]+[^;]+;' "$sol" 2>/dev/null \
            | sed -E 's/.*pragma[[:space:]]+solidity[[:space:]]+([^;]+);.*/\1/' >> "$tmp"
    done < <(find "$SRC_DIR" -name "*.sol" \
        -not -path "*/test/*" \
        -not -path "*/lib/*" \
        -not -path "*/node_modules/*" \
        -not -path "*/script/*" \
        -print0 2>/dev/null)
    sort -u "$tmp" | awk 'NF { c++ } END { print c+0 }'
    rm -f "$tmp"
}

count_nondefault_profile_srcs() {
    [ -f "$WS/foundry.toml" ] || { echo 0; return; }
    awk '
        /^\[profile\./ {
            profile = $0
            sub(/^\[profile\./, "", profile)
            sub(/\]$/, "", profile)
            next
        }
        profile != "" && /^[[:space:]]*src[[:space:]]*=/ {
            if (profile != "default") seen[profile] = 1
        }
        END {
            c = 0
            for (k in seen) c++
            print c+0
        }
    ' "$WS/foundry.toml"
}

has_nested_foundry_toml() {
    find "$SRC_DIR" -mindepth 2 -name "foundry.toml" -print -quit 2>/dev/null | grep -q .
}

STATIC_COMPLEX_PRAGMAS=0
STATIC_COMPLEX_PROFILES=0
STATIC_COMPLEX_NESTED=0
STATIC_COMPLEX_REASON=""
static_analysis_needs_multisolc() {
    STATIC_COMPLEX_PRAGMAS=$(count_distinct_pragmas)
    STATIC_COMPLEX_PROFILES=$(count_nondefault_profile_srcs)
    if has_nested_foundry_toml; then
        STATIC_COMPLEX_NESTED=1
    else
        STATIC_COMPLEX_NESTED=0
    fi

    STATIC_COMPLEX_REASON=""
    if [ "${STATIC_COMPLEX_PRAGMAS:-0}" -gt 1 ]; then
        STATIC_COMPLEX_REASON="mixed pragmas (${STATIC_COMPLEX_PRAGMAS})"
    fi
    if [ "${STATIC_COMPLEX_PROFILES:-0}" -gt 0 ]; then
        if [ -n "$STATIC_COMPLEX_REASON" ]; then
            STATIC_COMPLEX_REASON="$STATIC_COMPLEX_REASON; "
        fi
        STATIC_COMPLEX_REASON="${STATIC_COMPLEX_REASON}non-default profile src blocks (${STATIC_COMPLEX_PROFILES})"
    fi
    if [ "${STATIC_COMPLEX_NESTED:-0}" -eq 1 ]; then
        if [ -n "$STATIC_COMPLEX_REASON" ]; then
            STATIC_COMPLEX_REASON="$STATIC_COMPLEX_REASON; "
        fi
        STATIC_COMPLEX_REASON="${STATIC_COMPLEX_REASON}nested foundry.toml"
    fi

    [ -n "$STATIC_COMPLEX_REASON" ]
}

run_static_analysis_baseline() {
    local mode="$1"
    local multisolc_helper="$AUDITOOOR_DIR/tools/scan-all-modules-multisolc.sh"
    local remap_helper="$AUDITOOOR_DIR/tools/fix-remappings.sh"
    local tmp_custom=""

    STATIC_ANALYSIS_MODE="$mode"
    if static_analysis_needs_multisolc && [ -x "$multisolc_helper" ] && command -v solc-select >/dev/null 2>&1; then
        echo "  [note] complex workspace detected — layering multisolc custom-detectors (${STATIC_COMPLEX_REASON})"
        if [ -x "$remap_helper" ] && [ -f "$WS/remappings.txt" -o -f "$WS/foundry.toml" ]; then
            bash "$remap_helper" "$WS" >/dev/null 2>&1 || true
        fi
        if bash "$multisolc_helper" "$WS" --force >/dev/null 2>&1; then
            tmp_custom=$(mktemp -t auditooor_multisolc_custom.XXXXXX)
            cp "$WS/custom-detectors.log" "$tmp_custom"
            CUSTOM_LOG_SOURCE="$tmp_custom" \
                bash "$AUDITOOOR_DIR/tools/run-slither.sh" "$WS" >/dev/null 2>&1 || true
            rm -f "$tmp_custom"
            STATIC_ANALYSIS_MODE="${mode} + multisolc custom-detectors"
            return
        fi
        echo "  [warn] multisolc custom-detector pass failed — falling back to run-slither.sh"
        STATIC_ANALYSIS_MODE="${mode} (fallback after multisolc failure)"
    elif static_analysis_needs_multisolc; then
        echo "  [warn] complex workspace detected (${STATIC_COMPLEX_REASON}) but solc-select/multisolc helper unavailable"
        STATIC_ANALYSIS_MODE="${mode} (complex workspace fallback)"
    fi

    bash "$AUDITOOOR_DIR/tools/run-slither.sh" "$WS" >/dev/null 2>&1 || true
}

# ---- Scan 1: Hexens query grep approximations ----
echo "[1/4] apply-queries.sh..."
QUERIES_OUT=$("$AUDITOOOR_DIR/tools/apply-queries.sh" "$SRC_DIR" 2>&1)
QUERY_HITS=$(echo "$QUERIES_OUT" | grep -c "\[HITS\]" || true)
QUERY_CLEAN=$(echo "$QUERIES_OUT" | grep -c "\[CLEAN\]" || true)
SCAN_RESULTS+=("Hexens queries: $QUERY_HITS hits / $((QUERY_HITS + QUERY_CLEAN)) checked")
echo "  $QUERY_HITS hits from $((QUERY_HITS + QUERY_CLEAN)) queries"

cat >> "$REPORT" <<EOF
## 1. Hexens Query Approximations

**Hits:** $QUERY_HITS / $((QUERY_HITS + QUERY_CLEAN)) queries

$(echo "$QUERIES_OUT" | grep "\[HITS\]" | sed 's/^/- /')

EOF

# ---- Scan 2: Pattern sweep (target-type filtered) ----
# R49 Bug 2: invoke once per listed type; apply-patterns accepts a single type,
# so we loop and append hits to the same PATTERN_HITS.md by re-running per type.
echo "[2/4] apply-patterns.sh for types: $TARGET_TYPE..."
PATTERN_HITS_TOTAL=0
PATTERN_TOTAL_TOTAL=0
IFS=',' read -ra _TYPES <<<"$TARGET_TYPE"
for t in "${_TYPES[@]}"; do
    t_trim=$(echo "$t" | tr -d ' ')
    [ -z "$t_trim" ] && continue
    PATTERN_OUT=$("$AUDITOOOR_DIR/tools/apply-patterns.sh" "$WS" --target-type "$t_trim" 2>&1)
    ph=$(echo "$PATTERN_OUT" | grep -oE '[0-9]+ with hits' | grep -oE '^[0-9]+' || echo 0)
    pt=$(echo "$PATTERN_OUT" | grep -oE '[0-9]+ patterns checked' | grep -oE '^[0-9]+' || echo 0)
    PATTERN_HITS_TOTAL=$(( PATTERN_HITS_TOTAL + ph ))
    PATTERN_TOTAL_TOTAL=$(( PATTERN_TOTAL_TOTAL + pt ))
    echo "  [$t_trim] $ph with hits / $pt checked"
done
SCAN_RESULTS+=("Patterns: $PATTERN_HITS_TOTAL with hits / $PATTERN_TOTAL_TOTAL checked (across: $TARGET_TYPE)")

cat >> "$REPORT" <<EOF
## 2. Pattern Sweep (target-type: $TARGET_TYPE)

**Patterns with hits:** $PATTERN_HITS_TOTAL / $PATTERN_TOTAL_TOTAL
**Full results:** \`PATTERN_HITS.md\`

EOF

# ---- Scan 3: Static analysis baseline ----
# R49 Bug 1 fix: don't skip merely because the file exists from scaffolding.
# A scaffolded static-analysis-summary.md from setup-workspace.sh is empty of
# real signal. Skip only when the file has POPULATED content (≥1 Slither/Aderyn
# hit OR an explicit "no findings" footer). --force-static overrides either way.
echo "[3/5] Static analysis baseline..."
sa_is_populated() {
    local f="$1"
    [ -f "$f" ] || return 1
    # Populated = has recognizable scan output from run-slither.sh. Pattern set:
    #   • "## Tool counts" table header (run-slither.sh v1 format)
    #   • "| slither" or "| aderyn" or "| semgrep" table row
    #   • explicit finding tables (High/Medium rows)
    #   • legacy "[done] total hits:" / "no findings" / "total findings: N" footers
    grep -qE '^## Tool counts|^\|[[:space:]]*(slither|aderyn|semgrep|custom detectors)|^\|?[[:space:]]*(High|Medium|Low|Informational)[[:space:]]*\||## (Slither|Aderyn|Semgrep) results|\[done\] total hits:|no findings$|total findings: [0-9]+' "$f" 2>/dev/null
}

if [ "$FORCE_STATIC" = 1 ]; then
    echo "  [--force-static] re-running regardless of existing summary"
    run_static_analysis_baseline "re-run (--force-static)"
    SCAN_RESULTS+=("Static analysis: $STATIC_ANALYSIS_MODE")
    printf "## 3. Static Analysis Baseline\n\n**Status:** %s.\n\n" "$STATIC_ANALYSIS_MODE" >> "$REPORT"
elif sa_is_populated "$WS/static-analysis-summary.md"; then
    SA_AGE=$(( ( $(date +%s) - $(stat -f %m "$WS/static-analysis-summary.md" 2>/dev/null || stat -c %Y "$WS/static-analysis-summary.md") ) / 86400 ))
    echo "  static-analysis-summary.md populated (${SA_AGE}d old)"
    if [ "$SA_AGE" -le 7 ]; then
        echo "  [skip] fresh + populated — not re-running (use --force-static to override)"
        SCAN_RESULTS+=("Static analysis: populated (${SA_AGE}d old)")
        printf "## 3. Static Analysis Baseline\n\n**Status:** populated summary, %sd old. Not re-run.\n\n" "$SA_AGE" >> "$REPORT"
    else
        echo "  [warn] stale (>7d) — should re-run with: bash tools/run-slither.sh $WS"
        SCAN_RESULTS+=("Static analysis: STALE (${SA_AGE}d old)")
        printf "## 3. Static Analysis Baseline\n\n**Status:** STALE (%sd old). Re-run: \`bash tools/run-slither.sh %s\`\n\n" "$SA_AGE" "$WS" >> "$REPORT"
    fi
else
    # File absent OR scaffolded (no real signal) — don't trust it; run SA.
    if [ -f "$WS/static-analysis-summary.md" ]; then
        echo "  [note] static-analysis-summary.md present but empty/scaffolded — running fresh SA"
    else
        echo "  [note] no static-analysis-summary.md — running fresh SA"
    fi
    run_static_analysis_baseline "freshly generated"
    if sa_is_populated "$WS/static-analysis-summary.md"; then
        SCAN_RESULTS+=("Static analysis: $STATIC_ANALYSIS_MODE")
        printf "## 3. Static Analysis Baseline\n\n**Status:** %s. See \`static-analysis-summary.md\`.\n\n" "$STATIC_ANALYSIS_MODE" >> "$REPORT"
    else
        SCAN_RESULTS+=("Static analysis: run FAILED or produced no signal")
        printf "## 3. Static Analysis Baseline\n\n**Status:** attempted run produced no signal. Inspect manually via \`bash tools/run-slither.sh %s\`.\n\n" "$WS" >> "$REPORT"
    fi
fi

# ---- Scan 4: Hypothesis generation ----
# ---- Scan 4: Solodit cross-reference search plan ----
# R49 Bug 2: run per listed type so hybrid workspaces get all relevant tags.
echo "[4/5] solodit-cross-ref.sh for types: $TARGET_TYPE..."
IFS=',' read -ra _TYPES <<<"$TARGET_TYPE"
for t in "${_TYPES[@]}"; do
    t_trim=$(echo "$t" | tr -d ' ')
    [ -z "$t_trim" ] && continue
    "$AUDITOOOR_DIR/tools/solodit-cross-ref.sh" "$WS" --type "$t_trim" >/dev/null 2>&1
done
SCAN_RESULTS+=("Solodit cross-ref: search plan generated")
echo "  search plan written to SOLODIT_SEARCH_PLAN.md"
echo "  Operator: execute each search via mcp__solodit__search_findings"

cat >> "$REPORT" <<EOF
## 4. Solodit Cross-Reference

**Status:** search plan generated at \`SOLODIT_SEARCH_PLAN.md\`.
Execute each search via \`mcp__solodit__search_findings\` using tag-based queries.
Multi-word keyword queries return 0 results 80%+ of the time — use tags + single keyword.

EOF

# ---- Scan 5: Hypothesis generation ----
echo "[5/5] generate-hypotheses.sh..."
if [ -f "$WS/HYPOTHESIS_PROMPT.md" ]; then
    echo "  [skip] HYPOTHESIS_PROMPT.md already exists"
    SCAN_RESULTS+=("Hypotheses: prompt exists")
else
    "$AUDITOOOR_DIR/tools/generate-hypotheses.sh" "$WS" --src src >/dev/null 2>&1
    echo "  prompt written to HYPOTHESIS_PROMPT.md"
    SCAN_RESULTS+=("Hypotheses: prompt generated")
fi

cat >> "$REPORT" <<EOF
## 5. Hypothesis Generation

**Status:** HYPOTHESIS_PROMPT.md ready. Feed to Claude for HYPOTHESES.md.

EOF

# ---- Summary ----
cat >> "$REPORT" <<EOF
---

## Summary

| Scan | Result |
|------|--------|
EOF

for r in "${SCAN_RESULTS[@]}"; do
    echo "| $(echo "$r" | cut -d: -f1) | $(echo "$r" | cut -d: -f2-) |" >> "$REPORT"
done

cat >> "$REPORT" <<EOF

---

### Recommended next actions for target type: $TARGET_TYPE

EOF

# R49 Bug 2: emit recommendation block for each listed type (primary first,
# secondaries after). Hybrid protocols get union of relevant checklists.
emit_recs() {
    local t="$1"
    case "$t" in
        exchange)
            cat >> "$REPORT" <<'EOF'
**exchange** —
1. Triage Hexens hits: `erc1155-transfer-before-state`, `downcast-uint256-to-smaller`, `unbounded-loop-external-call`, `setters-with-no-access-control`
2. Order flow analysis: trace `matchOrders` → `_settleMakerOrders` → `_settleTakerOrder` for balance accounting bugs
3. Signature verification: all sig types (EOA, proxy, safe, 1271) for replay/forgery
4. Event emission parity: assembly emit offsets vs event declarations
5. Deploy-state enumeration: `cast call` every admin/role/owner
6. Fee math fuzz: 10k-order fuzzing on CalculatorHelper/Fees paths
7. Reentrancy on ERC-1155 `safeTransferFrom` callbacks

EOF
            ;;
        lending)
            cat >> "$REPORT" <<'EOF'
**lending** —
1. Liquidation math: thresholds, LTV, oracle freshness
2. Interest rate model: fuzz compound/accrue for precision loss
3. Collateral factor manipulation: can governance trigger instant liquidation?
4. Flash loan interactions on utilization/rates
5. Bad debt socialization when collateral < debt

EOF
            ;;
        vault)
            cat >> "$REPORT" <<'EOF'
**vault** —
1. First depositor attack: share price manipulation via donation
2. Withdrawal queue: can it be blocked or front-run?
3. ERC4626 rounding: fuzz deposit/withdraw/mint/redeem directions
4. Yield accounting donation attacks
5. Strategy migration during rebalancing

EOF
            ;;
        bridge)
            cat >> "$REPORT" <<'EOF'
**bridge** —
1. Replay protection: per-message nonce consumption on the receive side
2. Message authentication: signer set / validator threshold enforcement
3. Token allowlist on receive: reject arbitrary ERC20 / fake tokens
4. Transfer-id / message-id verification: no action on user-supplied ids
5. Cross-chain decimals + source-chain-id binding in digest

EOF
            ;;
        dex)
            cat >> "$REPORT" <<'EOF'
**dex** —
1. Swap invariant (k / constant-product) preserved across fee math
2. Oracle/price manipulation via flash loan on thin liquidity
3. Slippage + deadline enforcement on all swap paths
4. Fee-on-transfer / rebasing token handling
5. LP mint/burn accounting at zero totalSupply

EOF
            ;;
        bundler)
            cat >> "$REPORT" <<'EOF'
**bundler** —
1. msg.sender vs signer on every bundled call
2. Reentrancy across batch steps touching shared state
3. Approval hygiene: no residual allowances after failed step
4. Gas-bomb / per-call gas limits in batch executor
5. Meta-tx replay across chains / nonces

EOF
            ;;
        *)
            cat >> "$REPORT" <<'EOF'
**general** —
1. Triage all HITS from Hexens queries
2. Review PATTERN_HITS.md for high-confidence matches
3. Run static analysis if not yet done
4. Feed HYPOTHESIS_PROMPT.md to Claude for targeted hypotheses

EOF
            ;;
    esac
}

IFS=',' read -ra _TYPES <<<"$TARGET_TYPE"
for t in "${_TYPES[@]}"; do
    t_trim=$(echo "$t" | tr -d ' ')
    [ -z "$t_trim" ] && continue
    emit_recs "$t_trim"
done

echo ""
echo "============================================================================"
echo "  Scan complete. Report: $REPORT"
echo ""
for r in "${SCAN_RESULTS[@]}"; do
    echo "  $r"
done
echo "============================================================================"
