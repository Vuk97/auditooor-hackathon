#!/usr/bin/env bash
# economic-hypotheses.sh — R61 Track A2: economic attack surface enumerator
#
# Given a Solidity contract (or directory), enumerate the economic attack
# surface.  Outputs a hypothesis markdown file the operator walks case-by-case.
# This is ENUMERATION — not "here's a bug" but "here's the surface, check each".
#
# Usage:
#   ./tools/economic-hypotheses.sh <contract.sol|dir> [--out <path>]
#
# Output:
#   <contract-dir>/economic_hypotheses/<basename>.md   (default)
#   or --out <path>

set -uo pipefail

die()  { printf '[error] %s\n' "$*" >&2; exit 1; }
info() { printf '[info]  %s\n' "$*" >&2; }

# ── argument parsing ──────────────────────────────────────────────────────────

TARGET=""
OUTFILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUTFILE="$2"; shift 2 ;;
        -*) die "Unknown option: $1" ;;
        *) TARGET="$1"; shift ;;
    esac
done

[[ -z "$TARGET" ]] && die "Usage: $0 <contract.sol|dir> [--out <path>]"
[[ -e "$TARGET" ]] || die "Target not found: $TARGET"

TARGET="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"

if [[ -d "$TARGET" ]]; then
    SOL_FILES=$(find "$TARGET" -name '*.sol' 2>/dev/null | sort)
    BASENAME=$(basename "$TARGET")
    BASEDIR="$TARGET"
else
    SOL_FILES="$TARGET"
    BASENAME=$(basename "$TARGET" .sol)
    BASEDIR=$(dirname "$TARGET")
fi

[[ -z "$SOL_FILES" ]] && die "No .sol files found under $TARGET"

if [[ -z "$OUTFILE" ]]; then
    OUTDIR="$BASEDIR/economic_hypotheses"
    mkdir -p "$OUTDIR"
    OUTFILE="$OUTDIR/${BASENAME}.md"
fi

info "Scanning: $TARGET"
info "Output:   $OUTFILE"

DATE="$(date '+%Y-%m-%d %H:%M')"

# ── grep helpers ──────────────────────────────────────────────────────────────

# Run a grep across SOL_FILES; return "file:line:content" lines; never fails
rg_hits() { grep -rn "$1" $SOL_FILES 2>/dev/null || true; }

# Count non-empty lines in a string
cnt() {
    local n
    n=$(printf '%s\n' "$1" | grep -c '[^[:space:]]' 2>/dev/null) || n=0
    printf '%s' "$n"
}

# Render up to 20 grep-result lines as markdown bullets
render() {
    local hits="$1" count=0 total
    total=$(echo "$hits" | grep -c . 2>/dev/null || echo 0)
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local f loc c
        f=$(echo "$line"  | cut -d: -f1)
        loc=$(echo "$line" | cut -d: -f2)
        c=$(echo "$line"   | cut -d: -f3- | sed 's/^ *//')
        printf '%s\n' "- \`$(basename "$f"):$loc\` — \`$c\`"
        (( count++ )) || true
        if [[ $count -ge 20 && $total -gt 20 ]]; then
            printf '%s\n' "- _(... $(( total - 20 )) more omitted)_"
            break
        fi
    done <<< "$hits"
}

# ── collect raw hits ──────────────────────────────────────────────────────────

ORACLE_HITS=$(rg_hits 'IAggregatorV3\|IOracle\|IChainlink\|latestAnswer\|latestRoundData\|getPrice\|getAnswer\|observe\|Chainlink\|settleAndGetPrice\|getRequest\|resolvedPrice')
FLASH_HITS=$(rg_hits 'onFlashLoan\|flashLoanCallback\|executeOperation\|uniswapV2Call\|uniswapV3SwapCallback\|doSwap\|flashCallback')
RATE_HITS=$(rg_hits 'getBorrowRate\|getSupplyRate\|rewardPerToken\|exchangeRate\|\.accrue\b\|rewardIndex\|borrowIndex\|supplyIndex\|accumulate')
SHARE_HITS=$(rg_hits 'totalSupply()\|balanceOf(address(this))\|totalAssets()\|totalShares\|convertToShares\|convertToAssets\|previewDeposit\|previewMint\|previewRedeem\|previewWithdraw')
LIQ_HITS=$(rg_hits '\bliquidate\b\|forceClose\b\|seize\b\|closePosition\b\|closeLoan\b')
SLIP_HITS=$(rg_hits 'minOut\|minAmountOut\|minShares\|slippage\|minReceived\|minimumOut\|minReturn')
FOT_HITS=$(rg_hits 'safeTransferFrom\|safeTransfer\|\.transferFrom\|\.transfer(')
STATE_VARS=$(rg_hits 'uint256\s\+public\b\|address\s\+public\b\|bool\s\+public\b\|mapping.*public\b\|bytes32\s\+public\b')
SETTER_HITS=$(rg_hits 'function set[A-Z]\|function update[A-Z]\|onlyOwner\b\|onlyAdmin\b\|onlyOperator\b')

N_ORACLE=$(cnt "$ORACLE_HITS")
N_FLASH=$(cnt "$FLASH_HITS")
N_RATE=$(cnt "$RATE_HITS")
N_SHARE=$(cnt "$SHARE_HITS")
N_LIQ=$(cnt "$LIQ_HITS")
N_SLIP=$(cnt "$SLIP_HITS")
N_FOT=$(cnt "$FOT_HITS")
N_STATE=$(cnt "$STATE_VARS")
N_SETTERS=$(cnt "$SETTER_HITS")

STALE_GUARD=$(cnt "$(rg_hits 'updatedAt\|heartbeat\|maxAge\|freshness\|stalePrice\|MAX_DELAY\|STALENESS')")
DELTA_GUARD=$(cnt "$(rg_hits 'balanceBefore\|balanceAfter\|_getBalance\|balance.*[Bb]efore\|balance.*[Aa]fter')")
HARDCODED_DEC=$(cnt "$(rg_hits '1e8\|1e18\|10\*\*8\|10\*\*18')")

TOTAL=$(( ${N_ORACLE:-0} + ${N_FLASH:-0} + ${N_RATE:-0} + ${N_SHARE:-0} + ${N_LIQ:-0} + ${N_SLIP:-0} + ${N_FOT:-0} + ${N_STATE:-0} ))

# ── write report ──────────────────────────────────────────────────────────────

{
cat <<HEADER
# Economic hypothesis surface — ${BASENAME}

Generated: ${DATE}
Source: \`${TARGET}\`

> ENUMERATION file — not a finding list.  Walk each hypothesis; dismiss or escalate.

---

## Summary table

| # | Category | Hits | Key signal |
|---|---|---|---|
| 1 | Oracle calls | ${N_ORACLE} | staleness guards: ${STALE_GUARD}, hard-coded decimals: ${HARDCODED_DEC} |
| 2 | Flashloan callbacks | ${N_FLASH} | — |
| 3 | Rate/reward computations | ${N_RATE} | — |
| 4 | LP/share math | ${N_SHARE} | balance-delta guards: ${DELTA_GUARD} |
| 5 | Liquidation paths | ${N_LIQ} | — |
| 6 | Slippage parameters | ${N_SLIP} | — |
| 7 | Fee-on-transfer | ${N_FOT} | balance-delta guards: ${DELTA_GUARD} |
| 8 | Cross-function state | ${N_STATE} | privileged setters: ${N_SETTERS} |

**Total hypothesis items**: ${TOTAL}

---

HEADER

# ── Section 1 ──
cat <<S1
## 1. Oracle calls (${N_ORACLE} hit(s))

Patterns: \`IAggregatorV3\`, \`latestAnswer/latestRoundData\`, \`getPrice\`, \`settleAndGetPrice\`, \`observe\`

**Staleness-check lines found**: ${STALE_GUARD} (search \`updatedAt\`, \`maxAge\`, \`heartbeat\`)
**Hard-coded decimals lines**: ${HARDCODED_DEC} (search \`1e8\`, \`1e18\`)

S1
[[ -n "$ORACLE_HITS" ]] && { render "$ORACLE_HITS"; echo ""; }
cat <<'S1H'
### Hypotheses (per call site above)
- [ ] Is the oracle result used in a mutative function (storage write follows read)?
- [ ] Is there a staleness check? (`block.timestamp - updatedAt < maxAge`)
- [ ] Is a sentinel "ignore price" (`type(int256).min`, `0`) handled to avoid mis-resolution?
- [ ] Is the oracle source a manipulable DEX TWAP vs a decentralised aggregator?
- **Attack**: flashloan-sandwich the oracle source, trigger the mutative call, repay → 1-block price manipulation.

S1H

# ── Section 2 ──
cat <<S2
---

## 2. Flashloan callbacks (${N_FLASH} hit(s))

Patterns: \`onFlashLoan\`, \`executeOperation\`, \`uniswapV2Call\`, \`uniswapV3SwapCallback\`, \`flashCallback\`

S2
[[ -n "$FLASH_HITS" ]] && { render "$FLASH_HITS"; echo ""; }
cat <<'S2H'
### Hypotheses
- [ ] Is `msg.sender` checked against a trusted lender whitelist?
- [ ] Is `initiator` checked against `address(this)` or an expected address?
- [ ] Is there a `nonReentrant` guard on the callback entry point?
- [ ] Does the callback read oracle state manipulable within the same tx?
- [ ] Is debt repayment enforced by balance-delta or by caller-supplied amount?
- **Attack**: call the callback directly (or via a rogue lender) with crafted calldata.

S2H

# ── Section 3 ──
cat <<S3
---

## 3. Rate / reward computations (${N_RATE} hit(s))

Patterns: \`getBorrowRate\`, \`rewardPerToken\`, \`exchangeRate\`, \`accrue\`, index variants

S3
[[ -n "$RATE_HITS" ]] && { render "$RATE_HITS"; echo ""; }
cat <<'S3H'
### Hypotheses
- [ ] Do all dependent reads (totalSupply, totalBorrow, index) use the *same* block snapshot?
- [ ] `x / y` rounding — does truncation favour the protocol (round down for user)?
- [ ] Is `totalSupply == 0` guarded before rate computation (division-by-zero)?
- [ ] Is the index applied *before* or *after* the balance update (index drift)?
- **Attack**: interleave calls across block boundaries or via re-entrancy to capture rounding dust at scale.

S3H

# ── Section 4 ──
cat <<S4
---

## 4. LP / share math (${N_SHARE} hit(s))

Patterns: \`totalSupply()\`, \`balanceOf(address(this))\`, \`totalAssets()\`, EIP-4626 preview fns

S4
[[ -n "$SHARE_HITS" ]] && { render "$SHARE_HITS"; echo ""; }
cat <<'S4H'
### Hypotheses
- [ ] First-deposit edge: is `totalSupply == 0` handled (virtual offset per EIP-4626)?
- [ ] Can `balanceOf(address(this))` or `totalAssets()` be inflated by a direct donation *in the same tx* before shares are issued?
- [ ] Does `deposit` round shares *down* (safe) and `redeem` round assets *down* (safe)?
- [ ] Is `totalAssets()` called once and reused, or called twice (opening drift window)?
- **Attack**: atomic donation → deposit → redeem to capture inflated share price.

S4H

# ── Section 5 ──
cat <<S5
---

## 5. Liquidation paths (${N_LIQ} hit(s))

Patterns: \`liquidate\`, \`forceClose\`, \`seize\`, \`closePosition\`, \`closeLoan\`

S5
[[ -n "$LIQ_HITS" ]] && { render "$LIQ_HITS"; echo ""; }
cat <<'S5H'
### Hypotheses
- [ ] Is the liquidation bonus computed on *pre-liquidation* collateral value (inflatable via oracle)?
- [ ] Is `require(msg.sender != borrower)` enforced (self-liquidation guard)?
- [ ] Can a partial liquidation front-run change health factor mid-call?
- [ ] Is the `resolved` / `closed` flag set at the *start* or *end* of the function?
- **Attack**: manipulate oracle UP → trigger liquidation → capture inflated bonus; or self-liquidate to receive own bonus.

S5H

# ── Section 6 ──
cat <<S6
---

## 6. Slippage parameters (${N_SLIP} hit(s))

Patterns: \`minOut\`, \`minAmountOut\`, \`minShares\`, \`slippage\`, \`minimumOut\`

S6
[[ -n "$SLIP_HITS" ]] && { render "$SLIP_HITS"; echo ""; }
cat <<'S6H'
### Hypotheses
- [ ] Is `minOut == 0` explicitly rejected? (callers may pass 0 to disable protection)
- [ ] Is the slippage check *before* state mutation, or only at the end (re-entrancy window)?
- [ ] Is there a `deadline` parameter alongside slippage? (without it: MEV delay attack)
- **Attack**: sandwich tx if `minOut = 0`; or re-enter between mutation and slippage check.

S6H

# ── Section 7 ──
cat <<S7
---

## 7. Fee-on-transfer awareness (${N_FOT} transfer call(s))

Transfer patterns found: ${N_FOT}
Balance-delta guards found: ${DELTA_GUARD}

S7
[[ -n "$FOT_HITS" ]] && { echo "### Transfer lines (sample)"; render "$FOT_HITS"; echo ""; }
cat <<'S7H'
### Hypotheses
- [ ] After `transferFrom(token, from, to, amount)`: does code assume `amount` received? If token has a fee, actual received = `amount - fee`.
- [ ] Is actual received amount computed as `balanceAfter - balanceBefore` (safe) rather than `amount` (unsafe)?
- [ ] Does withdrawal logic send `amount` but vault only holds `amount * (1 - fee/bps)`?
- **Attack**: deposit fee-on-transfer token → vault credits full amount → redeem for more than was deposited.

S7H

# ── Section 8 ──
cat <<S8
---

## 8. Cross-function state reuse (${N_STATE} public state var(s), ${N_SETTERS} privileged setter(s))

S8

if [[ -n "$STATE_VARS" ]]; then
    echo "### Public state variables (first 12)"
    echo "$STATE_VARS" | head -12 | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        f=$(echo "$line" | cut -d: -f1); loc=$(echo "$line" | cut -d: -f2)
        c=$(echo "$line" | cut -d: -f3- | sed 's/^ *//')
        printf '%s\n' "- \`$(basename "$f"):$loc\` — \`$c\`"
    done
    echo ""
fi

if [[ -n "$SETTER_HITS" ]]; then
    echo "### Privileged setters (first 12)"
    echo "$SETTER_HITS" | head -12 | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        f=$(echo "$line" | cut -d: -f1); loc=$(echo "$line" | cut -d: -f2)
        c=$(echo "$line" | cut -d: -f3- | sed 's/^ *//')
        printf '%s\n' "- \`$(basename "$f"):$loc\` — \`$c\`"
    done
    echo ""
fi

cat <<'S8H'
### Hypotheses
- [ ] Can an admin call `setFeeReceiver` / `setMaxFeeRate` while a large user tx is in-flight (same block)?
- [ ] Can a user front-run `setMaxFeeRate(0)` then submit an order with 100% fee?
- [ ] Are packed storage slots (single SLOAD) written with separate SSTOREs (intermediate inconsistency)?
- [ ] Does `pause()` / `unpause()` race allow a user to drain while unpause is pending?
- **Attack**: mempool-monitor admin txs; sandwich with user tx that exploits the transitional state.

S8H

# ── Overall recommendation ──
cat <<FOOTER

---

## Overall recommendation

**Prioritize hypotheses in this order**:
1. Oracle manipulation + mutative write in same function (§1)
2. Unverified flashloan callback entry points (§2)
3. Self-liquidation / inflated liquidation bonus (§5)
4. First-deposit / donation attack on share math (§4)
5. Rate/index drift via interleaved calls (§3)
6. Zero-slippage and post-mutation slippage checks (§6)
7. Fee-on-transfer accounting gaps (§7)
8. Admin front-run races (§8)

**High-risk combinations to check explicitly**:
- Oracle read + mutative write inside liquidation path → amplified manipulation profit
- No staleness check + no TWAP + manipulable oracle source → 1-block sandwich
- \`totalAssets()\` as denominator without prior \`accrue()\` call → donation attack
- Flashloan callback with no sender check + oracle read → full oracle manipulation in 1 tx

**Suggested detectors to run**:
\`\`\`
ec-oracle-manipulation   # oracle read + write in same function
ec-oracle-staleness      # missing updatedAt check
ec-flashloan-nocheck     # unverified flashloan initiator
ec-share-donation        # totalAssets denominator without virtual offset
ec-liquidation-self      # missing msg.sender != borrower guard
ec-slippage-zero         # minOut == 0 not rejected
ec-fot-fixed-amount      # transfer without balance-delta check
\`\`\`
FOOTER

} > "$OUTFILE"

LINES=$(wc -l < "$OUTFILE" | tr -d ' ')
info "Done. ${LINES} lines → $OUTFILE"
printf '%s\n' "$OUTFILE"
