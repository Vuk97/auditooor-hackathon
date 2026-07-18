#!/usr/bin/env bash
# solodit-cross-ref.sh — cross-reference audit findings against Solodit corpus
#
# Usage:
#   ./tools/solodit-cross-ref.sh <workspace> [--type exchange|lending|vault|bridge|dex]
#
# Runs targeted Solodit API searches using TAGS (not free-text keywords)
# matched to the target type. Outputs <workspace>/SOLODIT_CROSS_REF.md.
#
# The Solodit API is keyword-sensitive: multi-word queries return 0 results
# 80%+ of the time. This script uses TAG-based searches with single short
# keywords, which is the only reliable query pattern.
#
# Rate limit: 20 calls per window. This script uses ~10-15 calls depending
# on target type, leaving headroom for manual follow-up.
#
# Fixes SKILL_ISSUES.md #75.

set -uo pipefail

# This script generates the SEARCH PLAN. The actual API calls must be made
# by the operator (Claude) using the mcp__solodit__search_findings tool,
# because bash cannot call MCP tools directly.
#
# Output: a structured search plan with exact parameters for each call.

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace> [--type exchange|lending|vault|bridge|dex]"
    exit 1
fi

WS="$1"
TARGET_TYPE="exchange"
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --type) TARGET_TYPE="$2"; shift 2 ;;
        *) shift ;;
    esac
done

OUT="$WS/SOLODIT_SEARCH_PLAN.md"

cat > "$OUT" <<HEADER
# Solodit Cross-Reference Search Plan

**Target type:** $TARGET_TYPE
**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Rate budget:** ~12 calls (of 20 per window)

## How to use

Run each search below using the \`mcp__solodit__search_findings\` tool.
Record hits in the Results column. For any HIGH/MEDIUM hit with quality >= 3,
fetch full details with \`mcp__solodit__get_finding\` and cross-reference
against FINDINGS.md / SCOPE_OUT_OF_SCOPE.md.

---

HEADER

case "$TARGET_TYPE" in
    exchange)
        cat >> "$OUT" <<'SEARCHES'
## Exchange-specific searches

| # | Tags | Keywords | Severity | Category | Purpose |
|---|------|----------|----------|----------|---------|
| 1 | `["Reentrancy"]` | `ERC1155 callback` | HIGH,MEDIUM | — | Callback reentrancy in token transfers |
| 2 | `["Business Logic"]` | `order settlement` | HIGH,MEDIUM | — | Order matching/settlement bugs |
| 3 | `["Access Control"]` | `role missing` | HIGH | — | Missing role grants (our #OFF.A class) |
| 4 | `["Overflow/Underflow"]` | `packed storage` | HIGH,MEDIUM | — | Assembly packing bugs (our #D14 class) |
| 5 | `["ERC20"]` | `balance drain` | HIGH | — | Balance accounting drain |
| 6 | `["Missing Check"]` | `signature replay` | HIGH | — | Sig verification bypass |
| 7 | — | — | HIGH,MEDIUM | `["Prediction Market"]` | ALL prediction market findings |
| 8 | `["Business Logic"]` | `cancel order` | HIGH,MEDIUM | — | Order cancellation bugs (our #V1.C class) |
| 9 | `["Reentrancy"]` | `nonReentrant missing` | HIGH | — | Missing reentrancy guard |
| 10 | `["Business Logic"]` | `refund surplus` | HIGH,MEDIUM | — | Refund/surplus accounting (our #R18.C class) |
| 11 | `["Missing Check"]` | `event emission` | LOW | — | Event parameter bugs (our #EV.F1/F2 class) |
| 12 | `["Fund Lock"]` | `withdrawal blocked` | HIGH | — | Permanent DoS on withdrawals |

## After searches

1. For each hit, check: does this class exist in our FINDINGS.md?
2. If YES: verify our closure rationale covers the specific variant
3. If NO: add to TODO.md as new iter target
4. Log all results in SESSION_LOG.md
SEARCHES
        ;;
    lending)
        cat >> "$OUT" <<'SEARCHES'
## Lending-specific searches

| # | Tags | Keywords | Severity | Category | Purpose |
|---|------|----------|----------|----------|---------|
| 1 | `["Liquidation"]` | `threshold manipulation` | HIGH | — | LTV/liquidation bypass |
| 2 | `["Oracle"]` | `price manipulation` | HIGH | — | Oracle price attacks |
| 3 | `["Flash Loan"]` | `utilization rate` | HIGH,MEDIUM | — | Flash loan rate manipulation |
| 4 | `["Rounding"]` | `interest accrual` | MEDIUM | — | Interest calculation precision |
| 5 | `["Business Logic"]` | `bad debt` | HIGH | — | Bad debt socialization |
| 6 | `["First Depositor Issue"]` | — | HIGH | — | First depositor attacks |
| 7 | `["Access Control"]` | `liquidation` | HIGH | — | Liquidation access control |
| 8 | `["Weird ERC20"]` | `rebase` | MEDIUM | — | Rebasing token issues |
SEARCHES
        ;;
    vault)
        cat >> "$OUT" <<'SEARCHES'
## Vault-specific searches

| # | Tags | Keywords | Severity | Category | Purpose |
|---|------|----------|----------|----------|---------|
| 1 | `["ERC4626"]` | — | HIGH,MEDIUM | — | ALL ERC4626 findings |
| 2 | `["First Depositor Issue"]` | — | HIGH | — | Share price manipulation |
| 3 | `["Rounding"]` | `deposit withdraw` | MEDIUM | — | Rounding direction |
| 4 | `["Business Logic"]` | `donation attack` | HIGH | — | Vault donation attacks |
| 5 | `["Slippage"]` | `withdrawal` | MEDIUM | — | Withdrawal slippage |
| 6 | `["Business Logic"]` | `strategy migration` | HIGH | — | Vault rebalancing bugs |
SEARCHES
        ;;
    *)
        cat >> "$OUT" <<'SEARCHES'
## General searches

| # | Tags | Keywords | Severity | Purpose |
|---|------|----------|----------|---------|
| 1 | `["Reentrancy"]` | — | HIGH | All reentrancy findings |
| 2 | `["Access Control"]` | — | HIGH | All access control findings |
| 3 | `["Business Logic"]` | — | HIGH | All business logic findings |
| 4 | `["Overflow/Underflow"]` | — | HIGH | All overflow findings |
SEARCHES
        ;;
esac

echo ""
echo "[done] Search plan written to: $OUT"
echo "  Run each search via mcp__solodit__search_findings"
echo "  Budget: ~12 API calls for target type '$TARGET_TYPE'"
