#!/usr/bin/env bash
# invariant-hunt.sh — R61 Track B: one-liner to go from contract → symbolic fuzz results.
#
# Usage:
#   ./tools/invariant-hunt.sh <workspace> <contract-class> [--contract <path>]
#
# Supported classes:
#   erc20 | erc4626 | erc7540 | exchange | lending | amm | bridge | staking
#   prediction-market | vault | perp
#
# Flow:
#   1. Discover target contract (if --contract not given)
#   2. Call gen-invariants.sh to emit harness
#   3. Fill protocol-default invariant bodies (class-specific)
#   4. Run forge invariant + halmos in parallel
#   5. Write <ws>/invariant_hunt/<class>.report.md
#
# Exit codes:
#   0 — all invariants PASS (or gracefully skipped)
#   1 — usage error / workspace not found
#   2 — at least one invariant BROKEN

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN_INV="$AUDITOOOR_DIR/tools/gen-invariants.sh"

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
usage() {
    cat >&2 <<'USAGE'
Usage: ./tools/invariant-hunt.sh <workspace> <contract-class> [--contract <path>]

Supported classes:
  erc20 erc4626 erc7540 exchange lending amm bridge staking
  prediction-market vault perp

Options:
  --contract <path>   Explicit .sol path; skips auto-discovery.

Example:
  ./tools/invariant-hunt.sh ~/audits/polymarket prediction-market \
    --contract ~/audits/polymarket/src/v1/neg-risk/NegRiskAdapter.sol
USAGE
    exit 1
}

[ $# -lt 2 ] && usage

WS="$1"
CLASS="$2"
CONTRACT_PATH=""
shift 2

while [ $# -gt 0 ]; do
    case "$1" in
        --contract) CONTRACT_PATH="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "[invariant-hunt] unknown arg: $1" >&2; usage ;;
    esac
done

[ -d "$WS" ] || { echo "[invariant-hunt] workspace not found: $WS" >&2; exit 1; }

KNOWN_CLASSES="erc20 erc4626 erc7540 exchange lending amm bridge staking prediction-market vault perp"
class_known=0
for c in $KNOWN_CLASSES; do [ "$c" = "$CLASS" ] && class_known=1 && break; done
if [ $class_known -eq 0 ]; then
    echo "[invariant-hunt] unknown class '$CLASS'. Known: $KNOWN_CLASSES" >&2
    exit 1
fi

OUT_DIR="$WS/invariant_hunt"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/${CLASS}.report.md"
DATE_TAG=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------------------
# Step 1: Discover target
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  invariant-hunt R61"
echo "  workspace : $WS"
echo "  class     : $CLASS"
echo "  started   : $DATE_TAG"
echo "============================================================"

discover_target() {
    # Candidate directories in priority order
    local search_dirs=()
    for d in "$WS/src" "$WS/contracts" "$WS"; do
        [ -d "$d" ] && search_dirs+=("$d")
    done
    [ ${#search_dirs[@]} -eq 0 ] && return 1

    # Class → interface signature patterns (same logic as gen-invariants.sh detect_class)
    local pattern=""
    case "$CLASS" in
        erc7540)         pattern='requestDeposit' ;;
        erc4626)         pattern='totalAssets|convertToShares' ;;
        exchange)        pattern='matchOrders|fillOrder|orderStatus|OrderStatus' ;;
        amm)             pattern='function swap|addLiquidity|getReserves' ;;
        lending)         pattern='function borrow|function repay|function liquidate|borrowIndex|utilization' ;;
        bridge)          pattern='sendMessage|lzReceive|outboundNonce|dstChainId' ;;
        staking)         pattern='function stake|function unstake|getReward|rewardPerToken' ;;
        prediction-market) pattern='getDetermined|reportOutcome|prepareMarket|reportPayouts|splitPosition' ;;
        vault)           pattern='totalAssets|totalDebt|maxWithdraw' ;;
        perp)            pattern='fundingIndex|openInterest|markPrice|getPositionSize' ;;
        erc20)           pattern='function transfer|function approve|function balanceOf' ;;
    esac

    local best_file=""
    local best_score=0

    while IFS= read -r sol; do
        # Skip test / lib / mock / interface / script
        case "$sol" in
            */test/*|*/lib/*|*/node_modules/*|*/mock*/*|*/script/*|*/snapshots/*) continue ;;
        esac
        local base; base=$(basename "$sol" .sol)
        case "$base" in I*|*Mock*|*Test*|*Script*) continue ;; esac

        # Must match class pattern
        if [ -n "$pattern" ]; then
            grep -Eq "$pattern" "$sol" 2>/dev/null || continue
        fi

        local loc; loc=$(wc -l < "$sol" | tr -d ' ')
        if [ "$loc" -gt "$best_score" ]; then
            best_score=$loc
            best_file="$sol"
        fi
    done < <(find "${search_dirs[@]}" -name "*.sol" 2>/dev/null)

    echo "$best_file"
}

if [ -z "$CONTRACT_PATH" ]; then
    echo "[1/5] Auto-discovering $CLASS contract in $WS ..."
    CONTRACT_PATH=$(discover_target)
    if [ -z "$CONTRACT_PATH" ]; then
        echo "[invariant-hunt] ERROR: could not auto-discover a $CLASS contract." >&2
        echo "  Use --contract <path> to specify explicitly." >&2
        exit 1
    fi
    echo "  Discovered: $CONTRACT_PATH"
else
    echo "[1/5] Using explicit contract: $CONTRACT_PATH"
    [ -f "$CONTRACT_PATH" ] || { echo "[invariant-hunt] contract not found: $CONTRACT_PATH" >&2; exit 1; }
fi

CONTRACT_NAME=$(basename "$CONTRACT_PATH" .sol)

# ---------------------------------------------------------------------------
# Step 2: Emit harness via gen-invariants.sh
# ---------------------------------------------------------------------------
echo ""
echo "[2/5] Generating invariant harness (class=$CLASS) ..."

HARNESS_DIR="$WS/poc-tests"
mkdir -p "$HARNESS_DIR"
HARNESS_FILE="$HARNESS_DIR/Invariant_${CONTRACT_NAME}.t.sol"
BRIEF_FILE="$OUT_DIR/${CLASS}_brief.md"

if [ ! -x "$GEN_INV" ]; then
    echo "[invariant-hunt] WARNING: gen-invariants.sh not executable or missing at $GEN_INV" >&2
    echo "  Skipping harness generation; harness must be present at $HARNESS_FILE"
else
    bash "$GEN_INV" "$CONTRACT_PATH" "$WS" --class "$CLASS" --brief-file "$BRIEF_FILE" 2>&1 | \
        sed 's/^/  [gen-inv] /'
fi

if [ ! -f "$HARNESS_FILE" ]; then
    echo "[invariant-hunt] ERROR: harness not found at $HARNESS_FILE after gen-invariants." >&2
    echo "  Check gen-invariants.sh output above." >&2
    exit 1
fi

echo "  Harness: $HARNESS_FILE"

# ---------------------------------------------------------------------------
# Step 3: Inject protocol-default invariant bodies
#         gen-invariants.sh already emits class-template bodies when the
#         template exists. This step logs what was emitted so the report
#         is self-contained, and patches the generic fallback if needed.
# ---------------------------------------------------------------------------
echo ""
echo "[3/5] Verifying protocol-default invariants in harness ..."

# Count how many real invariant_* functions were emitted (non-placeholder)
INV_COUNT=$(grep -cE '^[[:space:]]+function invariant_' "$HARNESS_FILE" 2>/dev/null || echo 0)
echo "  invariant_* functions found: $INV_COUNT"

if [ "$INV_COUNT" -le 1 ]; then
    # Generic fallback only emits invariant_placeholder. Warn but don't abort.
    echo "  [WARN] Only placeholder invariant found. Template for class '$CLASS' may be missing."
    echo "         Check $AUDITOOOR_DIR/reference/invariant_class_templates/${CLASS}.sol.template"
    echo "         Results will be minimal; add custom invariants manually."
fi

# ---------------------------------------------------------------------------
# Step 4: Run forge invariant + halmos in parallel
# ---------------------------------------------------------------------------
echo ""
echo "[4/5] Running forge invariant + halmos ..."

FORGE_LOG="$OUT_DIR/${CLASS}_forge.log"
HALMOS_LOG="$OUT_DIR/${CLASS}_halmos.log"

# Detect forge
HAVE_FORGE=0
command -v forge >/dev/null 2>&1 && HAVE_FORGE=1

# Detect halmos
HAVE_HALMOS=0
command -v halmos >/dev/null 2>&1 && HAVE_HALMOS=1
[ $HAVE_HALMOS -eq 0 ] && echo "  halmos not installed; skipping symbolic layer; foundry invariant still runs"

# Determine the best forge profile and test directory for the generated harness.
# Strategy:
#   1. Use poc profile if foundry.toml has it with src="poc-tests"
#   2. If no matching profile or profile fails to compile, copy harness to first
#      working profile's test dir and run there.
#   3. Fall back to default profile with --match-path.
FORGE_PROFILE=""
FORGE_SRC_FLAG="--match-contract Invariant_${CONTRACT_NAME}"
FORGE_EXTRA=""
FORGE_HARNESS_COPY=""  # if we copy to another dir, track it for cleanup note

# R70 SKILL_ISSUES #174: auto-locate nested foundry.toml. Many audit
# workspaces (Cantina canonical layout: $WS/src/<repo>/foundry.toml,
# Snowbridge-style: $WS/src/<repo>/contracts/foundry.toml, etc.) place
# the forge project one or two directories below the workspace root.
# Previously, invariant-hunt required foundry.toml AT $WS and silently
# skipped forge-run on nested layouts. Walk up to 4 levels deep and, if
# we find a foundry.toml, switch the working root so forge/halmos runs
# against it.
FORGE_WS="$WS"  # the root forge will cd into
if [ ! -f "$FORGE_WS/foundry.toml" ]; then
    _candidate=$(find "$WS" -maxdepth 4 -name foundry.toml -not -path '*/lib/*' -not -path '*/out/*' -not -path '*/cache/*' 2>/dev/null | head -1)
    if [ -n "$_candidate" ]; then
        FORGE_WS=$(dirname "$_candidate")
        echo "[invariant-hunt] R70: auto-located nested foundry.toml at $_candidate"
        echo "                using FORGE_WS=$FORGE_WS for forge/halmos runs"
    fi
fi

if [ -f "$FORGE_WS/foundry.toml" ]; then
    _harness_dirname=$(basename "$HARNESS_DIR")   # e.g. "poc-tests"

    # Extract all top-level [profile.X] names (skip sub-sections like profile.default.rpc_storage_caching)
    _all_profiles=$(grep -E '^\[profile\.[a-zA-Z0-9_]+\]$' "$FORGE_WS/foundry.toml" 2>/dev/null | \
        sed 's/\[profile\.\([^]]*\)\]/\1/')

    # Find a working profile: prefer profile whose src == harness dir, but only if it compiles.
    # Fall back to profiles with other src dirs (copy harness there).
    _FORGE_FOUND_PROFILE=""
    _FORGE_FOUND_SRC=""

    for _try_profile in $_all_profiles; do
        _try_src=$(awk -v p="\[profile.${_try_profile}\]" '
            $0 == p { found=1; next }
            found && /^\[/ { found=0 }
            found && /^src[[:space:]]*=/ {
                gsub(/.*=[[:space:]]*"/, ""); gsub(/".*/, ""); print; exit
            }
        ' "$FORGE_WS/foundry.toml" 2>/dev/null)
        [ -z "$_try_src" ] && continue
        _try_dir="$WS/$_try_src"
        [ -d "$_try_dir" ] || continue

        # Quick compile check: does this profile compile without errors?
        _profile_env=""
        [ "$_try_profile" != "default" ] && _profile_env="FOUNDRY_PROFILE=${_try_profile}"
        _compile_ok=0
        (
            cd "$FORGE_WS"
            eval "${_profile_env}" forge build --silent 2>&1 | grep -qiE '^Error:|invalid solc' && exit 1
            exit 0
        ) 2>/dev/null && _compile_ok=1

        if [ $_compile_ok -eq 1 ]; then
            # If harness is already in this dir, use directly
            if [ "$_try_dir" = "$HARNESS_DIR" ]; then
                _FORGE_FOUND_PROFILE="$_try_profile"
                _FORGE_FOUND_SRC="$_try_src"
                break
            fi
            # Else copy harness here
            _copied_harness="$_try_dir/Invariant_${CONTRACT_NAME}.t.sol"
            cp "$HARNESS_FILE" "$_copied_harness" 2>/dev/null && {
                FORGE_HARNESS_COPY="$_copied_harness"
                _FORGE_FOUND_PROFILE="$_try_profile"
                _FORGE_FOUND_SRC="$_try_src"
                echo "  [profile] harness copied to $_copied_harness (profile: ${_try_profile})"
                break
            }
        fi
    done

    if [ -n "$_FORGE_FOUND_PROFILE" ]; then
        [ "$_FORGE_FOUND_PROFILE" = "default" ] && FORGE_PROFILE="" || FORGE_PROFILE="FOUNDRY_PROFILE=${_FORGE_FOUND_PROFILE}"
        FORGE_SRC_FLAG="--match-contract Invariant_${CONTRACT_NAME}"
        echo "  [profile] using foundry profile: ${_FORGE_FOUND_PROFILE} (src=${_FORGE_FOUND_SRC})"
    else
        # Total fallback: no compilable profile found; try default with match-path
        FORGE_EXTRA="--match-path ${_harness_dirname}/Invariant_${CONTRACT_NAME}.t.sol"
        FORGE_SRC_FLAG=""
        echo "  [profile] WARNING: no cleanly-compiling profile found; using default + match-path"
    fi
fi

FORGE_EXIT=0
HALMOS_EXIT=0

# Run forge in the background
if [ $HAVE_FORGE -eq 1 ] && [ -f "$FORGE_WS/foundry.toml" ]; then
    echo "  Starting: forge test (invariant) ..."
    (
        cd "$FORGE_WS"
        # Clear cached invariant failure files for this harness to avoid stale replays
        rm -rf "$WS/cache/invariant/failures/Invariant_${CONTRACT_NAME}" 2>/dev/null || true
        # --invariant-runs / --invariant-depth are foundry.toml knobs, not CLI flags
        # in older forge versions. Override via env vars if supported; fall back gracefully.
        FOUNDRY_INVARIANT_RUNS=5000 FOUNDRY_INVARIANT_DEPTH=50 \
        eval "${FORGE_PROFILE}" forge test \
            ${FORGE_SRC_FLAG} ${FORGE_EXTRA} \
            -v 2>&1
    ) > "$FORGE_LOG" 2>&1 &
    FORGE_PID=$!
else
    echo "  [SKIP] forge not installed or no foundry.toml in workspace" | tee "$FORGE_LOG"
    FORGE_PID=""
fi

# Run halmos in the background
if [ $HAVE_HALMOS -eq 1 ] && [ -f "$FORGE_WS/foundry.toml" ]; then
    echo "  Starting: halmos (symbolic) ..."
    (
        cd "$FORGE_WS"
        halmos --match-contract "Invariant_${CONTRACT_NAME}" 2>&1
    ) > "$HALMOS_LOG" 2>&1 &
    HALMOS_PID=$!
else
    [ $HAVE_HALMOS -eq 0 ] && echo "[halmos not installed; symbolic layer skipped]" > "$HALMOS_LOG"
    HALMOS_PID=""
fi

# Wait for both
[ -n "$FORGE_PID" ] && wait "$FORGE_PID"; FORGE_EXIT=${PIPESTATUS[0]:-$?}
[ -n "$HALMOS_PID" ] && wait "$HALMOS_PID"; HALMOS_EXIT=${PIPESTATUS[0]:-$?}

echo "  forge log  : $FORGE_LOG (exit $FORGE_EXIT)"
echo "  halmos log : $HALMOS_LOG (exit $HALMOS_EXIT)"

# R73 C3: if forge completed but reported 0 BROKEN, try halmos as a fallback.
# Halmos is symbolic — catches path-sensitive bugs that exponential-state
# forge fuzz misses. If halmos was already run, this is a no-op.
if [ $HAVE_FORGE -eq 1 ] && [ $HAVE_HALMOS -eq 0 ] && [ $FORGE_EXIT -eq 0 ]; then
    _forge_broken=$(grep -cE '\[FAIL|invariant.*FAIL|Counterexample' "$FORGE_LOG" 2>/dev/null || echo 0)
    if [ "$_forge_broken" -eq 0 ]; then
        echo ""
        echo "  [R73 C3 hint] forge reported 0 BROKEN invariants but halmos is NOT installed."
        echo "  Path-sensitive coverage is currently OFF. To enable:"
        echo "      pip3 install halmos   # pulls z3-solver (~100MB)"
        echo "  Then re-run:  bash tools/invariant-hunt.sh $WS $CLASS --contract $CONTRACT_PATH"
        echo "  Halmos finds bugs in states that forge's random fuzz misses."
    fi
fi

# ---------------------------------------------------------------------------
# Step 5: Parse results and write report
# ---------------------------------------------------------------------------
echo ""
echo "[5/5] Parsing results and writing report ..."

# Parse forge output
parse_forge() {
    local log="$1"
    [ -f "$log" ] || { echo "SKIP"; return; }

    # Forge invariant output format (multi-line blocks):
    #   [FAIL: <reason>]                                     ← reason line
    #     [Sequence] ...
    #     sender=... calldata=... args=...
    #    invariant_foo() (runs: N, calls: M, reverts: R)     ← invariant + stats line
    #
    # We use awk to track consecutive FAIL blocks and detect:
    #   SETUP FAILURE: reason="call to non-contract address 0x0..." AND runs=0
    #   REAL BREAK: any other failure reason OR runs>0
    local result
    result=$(awk '
        /^\[FAIL/ {
            fail_reason=$0
            is_setup=0
            # Setup failure patterns:
            #   1. call to non-contract address 0x0...0 (target not deployed)
            #   2. "replay failure" (cached failure from previous run with unwired setUp)
            if (fail_reason ~ /call to non-contract address 0x0/ ||
                fail_reason ~ /replay failure/) is_setup=1
            next
        }
        /invariant_[A-Za-z_0-9]+\(\)/ && fail_reason != "" {
            fn=$0
            gsub(/.*invariant_/, "invariant_", fn)
            gsub(/\(.*/, "", fn)
            runs_val=0
            reverts_val=0
            calls_val=0
            if (match($0, /runs: [0-9]+/)) {
                r=substr($0, RSTART+6, RLENGTH-6)
                runs_val=r+0
            }
            if (match($0, /calls: [0-9]+/)) {
                r=substr($0, RSTART+7, RLENGTH-7)
                calls_val=r+0
            }
            if (match($0, /reverts: [0-9]+/)) {
                r=substr($0, RSTART+9, RLENGTH-9)
                reverts_val=r+0
            }
            # Setup failure: is_setup=1 OR (calls==reverts — every call reverted, no real execution)
            if (is_setup || (calls_val > 0 && calls_val == reverts_val && runs_val <= 1)) {
                print "SETUP_FAIL:" fn
            } else {
                print "BROKEN:" fn
            }
            fail_reason=""
            next
        }
        /^\[PASS\]/ { print "PASS"; next }
        /invariant_[A-Za-z_0-9]+\(\).*\(runs:/ {
            # PASS lines in summary section (no preceding FAIL)
            if (fail_reason == "") print "PASS"
        }
    ' "$log")

    local passes=0 fails=0 setup_fails=0 fail_list=""
    while IFS= read -r r; do
        case "$r" in
            PASS)             passes=$((passes+1)) ;;
            BROKEN:*)         fails=$((fails+1));       fn="${r#BROKEN:}";      fail_list="${fail_list}  - BROKEN: ${fn}\n" ;;
            SETUP_FAIL:*)     setup_fails=$((setup_fails+1)); fn="${r#SETUP_FAIL:}"; fail_list="${fail_list}  - SETUP_FAIL (setUp not wired): ${fn}\n" ;;
        esac
    done <<< "$result"

    echo "forge_passes=$passes"
    echo "forge_fails=$fails"
    echo "forge_setup_fails=$setup_fails"
    printf "forge_fail_list=%s" "$fail_list"
}

# Parse halmos output
parse_halmos() {
    local log="$1"
    [ -f "$log" ] || { echo "SKIP"; return; }
    grep -q 'not installed' "$log" 2>/dev/null && { echo "SKIP"; return; }

    local ces=0
    local ce_list=""
    while IFS= read -r line; do
        if echo "$line" | grep -qE '^\[FAIL\]|Counterexample:'; then
            ces=$((ces + 1))
            fn=$(echo "$line" | grep -oE 'check_[A-Za-z_0-9]+|invariant_[A-Za-z_0-9]+' | head -1)
            [ -z "$fn" ] && fn="unknown"
            ce_list="${ce_list}  - BROKEN (symbolic CE): ${fn}\n"
        fi
    done < "$log"

    echo "halmos_ces=$ces"
    printf "halmos_ce_list=%s" "$ce_list"
}

FORGE_PARSED=$(parse_forge "$FORGE_LOG")
HALMOS_PARSED=$(parse_halmos "$HALMOS_LOG")

forge_passes=$(echo "$FORGE_PARSED" | grep '^forge_passes=' | cut -d= -f2)
forge_fails=$(echo "$FORGE_PARSED"  | grep '^forge_fails='  | cut -d= -f2)
forge_fail_list=$(echo "$FORGE_PARSED" | grep '^forge_fail_list=' | sed 's/^forge_fail_list=//')

halmos_ces=$(echo "$HALMOS_PARSED"    | grep '^halmos_ces=' | cut -d= -f2)
halmos_ce_list=$(echo "$HALMOS_PARSED" | grep '^halmos_ce_list=' | sed 's/^halmos_ce_list=//')

forge_passes=${forge_passes:-0}
forge_fails=${forge_fails:-0}
forge_setup_fails=$(echo "$FORGE_PARSED" | grep '^forge_setup_fails=' | cut -d= -f2)
forge_setup_fails=${forge_setup_fails:-0}
halmos_ces=${halmos_ces:-0}

TOTAL_BROKEN=$(( forge_fails + halmos_ces ))
NOVEL_FLAG=""
SETUP_WARN=""
[ "$TOTAL_BROKEN" -gt 0 ] && NOVEL_FLAG="**NOVEL-CANDIDATE: $TOTAL_BROKEN invariant(s) BROKEN — investigate for submission.**"
[ "$forge_setup_fails" -gt 0 ] && SETUP_WARN="**SETUP-INCOMPLETE: $forge_setup_fails invariant(s) failed due to setUp() not wired (target=address(0)). Wire setUp() to get real results.**"

# Write report
cat > "$REPORT" <<EOF
# Invariant Hunt Report — $CONTRACT_NAME (class: $CLASS)

**Generated:** $DATE_TAG
**Workspace:** \`$WS\`
**Contract:**  \`$CONTRACT_PATH\`
**Harness:**   \`$HARNESS_FILE\`
**Class:**     $CLASS

---

## Summary

| Layer | Tested | PASS | BROKEN | Setup Fails |
|-------|--------|------|--------|-------------|
| forge invariant | $((forge_passes + forge_fails + forge_setup_fails)) | $forge_passes | $forge_fails | $forge_setup_fails |
| halmos symbolic | — | — | $halmos_ces | — |
| **Total** | — | — | **$TOTAL_BROKEN** | $forge_setup_fails |

$SETUP_WARN
$NOVEL_FLAG

---

## Invariant Functions Emitted

$(grep -E '^[[:space:]]+function invariant_' "$HARNESS_FILE" 2>/dev/null | sed 's/.*function /- `/' | sed 's/(.*$/`()/' || echo "_(none found)_")

---

## Forge Invariant Results

\`\`\`
$(tail -80 "$FORGE_LOG" 2>/dev/null || echo "(no forge log)")
\`\`\`

### Broken invariants (forge):
$([ "$forge_fails" -gt 0 ] && printf "%b" "$forge_fail_list" || echo "None — all PASS or test skipped.")

---

## Halmos Symbolic Results

\`\`\`
$(tail -60 "$HALMOS_LOG" 2>/dev/null || echo "(no halmos log)")
\`\`\`

### Counter-examples (halmos):
$([ "$halmos_ces" -gt 0 ] && printf "%b" "$halmos_ce_list" || echo "None — symbolic layer clean or skipped.")

---

## Class-default Invariant Rationale ($CLASS)

EOF

# Append class-specific rationale
case "$CLASS" in
  erc4626)
cat >> "$REPORT" <<'EOF'
- **invariant_share_price_monotone**: share price (assets per share) must not decrease without explicit fee accrual — violations indicate donation griefing or free-mint bugs.
- **invariant_preview_matches_actual_deposit**: previewDeposit/previewRedeem round-trip skew breaks ERC-4626 spec, enabling precision-loss attacks.
- **invariant_totalAssets_covers_shares**: no user should be able to redeem more than totalAssets — phantom asset invariant.
- **invariant_deposit_redeem_roundtrip**: users must get back within 1 wei of deposited assets.
EOF
;;
  lending)
cat >> "$REPORT" <<'EOF'
- **invariant_solvency**: pool totalAssets >= totalLiabilities — core solvency.
- **invariant_borrow_index_monotone**: interest accumulation is irreversible.
- **invariant_liquidation_incentive_bounded**: liquidators can't extract more than the configured cap.
- **invariant_utilization_bounded**: pool can't lend out more than 100% of deposits.
- **invariant_borrows_covered**: total borrows <= total assets at all times.
EOF
;;
  exchange)
cat >> "$REPORT" <<'EOF'
- **invariant_order_status_one_way**: order status transitions are monotone; filled/cancelled are terminal.
- **invariant_fee_bounded**: fees collected <= maxFeeRateBps * volume.
- **invariant_collateral_conservation**: collateral balance == credits - debits.
- **invariant_filled_has_zero_remaining**: a filled order must have zero remaining quantity.
EOF
;;
  prediction-market)
cat >> "$REPORT" <<'EOF'
- **invariant_determined_once_per_market**: once a neg-risk market is determined, it cannot revert to undetermined. Violations indicate state-machine bug.
- **invariant_at_most_one_winner_per_market**: only one question per market can resolve YES — the core neg-risk invariant. Violations enable double-payout exploits.
- **invariant_fee_within_bounds**: feeBips <= 10_000 (100%). Overflow/admin bypass could set uncapped fees.
- **invariant_oracle_nonzero_for_prepared_markets**: prepared markets must retain their oracle address — zeroing it would allow re-initialization.
- **invariant_payout_sum_equals_denominator** (commented out): YES + NO payout numerators must sum to denominator per CTF spec.
EOF
;;
  amm)
cat >> "$REPORT" <<'EOF'
- **invariant_k_nondecreasing**: x*y product must not decrease between swaps (fees only increase k).
- **invariant_reserves_nonzero_with_liquidity**: pool reserves should remain nonzero while LP supply > 0.
- **invariant_fee_bounded**: swap fee <= max configured fee.
EOF
;;
  vault)
cat >> "$REPORT" <<'EOF'
- **invariant_solvency**: totalAssets >= totalDebt at all times.
- **invariant_max_withdraw_bounded_by_total_assets**: no actor can have maxWithdraw > totalAssets.
- **invariant_no_over_commitment**: sum of all maxWithdraw <= totalAssets (anti-overcommitment).
- **invariant_asset_nonzero**: vault's underlying asset address must remain non-zero.
EOF
;;
  perp)
cat >> "$REPORT" <<'EOF'
- **invariant_system_solvency**: clearing house margin >= totalOI * markPrice / maxLeverage.
- **invariant_no_negative_margin**: individual trader margin + unrealizedPnl >= 0 (should be liquidated first).
- **invariant_long_short_balance_bounded**: net open interest is bounded by totalOI.
- **invariant_leverage_bounded**: per-account notional / margin <= maxLeverage.
EOF
;;
  *)
    echo "_(see reference/invariant_templates.yaml for this class)_" >> "$REPORT"
;;
esac

cat >> "$REPORT" <<EOF

---

## Known gen-invariants.sh Bugs / Gotchas Observed This Run

- Template substitution uses perl \`-pe\`; the harness path written into the import comment may need adjustment if src layout differs from the template.
- setUp() remains commented-out (\`// target = new ...\`) — **operators must uncomment and wire constructors before forge will compile**.
- When the workspace foundry.toml uses a non-default profile (e.g. \`poc\`), invoke as \`FOUNDRY_PROFILE=poc forge test ...\`
- The NegRiskAdapter's CTF + collateral are immutable constructor args; the harness requires mock deployments in setUp() to compile (see poc-tests/Invariant_CTFExchange.t.sol for an example using \`vm.etch\`).
- halmos requires halmos-compatible solc version; if project uses \`via_ir\` the symbolic pass may hit stack depth. Pass \`--no-compilation\` after pre-building.

---

## Next Actions

1. Wire setUp() in \`$HARNESS_FILE\` — deploy real or mocked target + dependencies.
2. Add class-specific handler mutators that call the target's entry points.
3. Re-run: \`FOUNDRY_PROFILE=poc forge test --match-contract Invariant_${CONTRACT_NAME} --invariant-runs 5000 --invariant-depth 50 -v\`
4. If halmos is available: \`cd $WS && halmos --match-contract Invariant_${CONTRACT_NAME}\`
5. Any BROKEN invariant with a counter-example → file as NOVEL-CANDIDATE submission draft.

EOF

echo "  Report: $REPORT"

echo ""
echo "============================================================"
echo "  invariant-hunt complete"
echo "  forge broken    : $forge_fails"
echo "  forge setup-fail: $forge_setup_fails (setUp() not wired — wire target in harness)"
echo "  halmos CEs      : $halmos_ces"
echo "  Total broken    : $TOTAL_BROKEN"
if [ "$TOTAL_BROKEN" -gt 0 ]; then
    echo "  *** NOVEL-CANDIDATE: investigate broken invariants ***"
fi
echo "  Report: $REPORT"
echo "============================================================"

[ "$TOTAL_BROKEN" -gt 0 ] && exit 2
exit 0
