#!/usr/bin/env bash
# gen-invariants.sh — scaffold Foundry invariant harness for a contract (Issue #102).
#
# U7 upgrade: class-aware generation. If --class is given (or auto-detected
# from source signatures), use the matching template from
# reference/invariant_class_templates/<class>.sol.template. Otherwise fall
# back to the generic StdInvariant skeleton + placeholder.
#
# I20 (#341): writes harness into the workspace's configured Foundry test dir
# (resolved from foundry.toml) instead of hardcoded poc-tests/.
#
# I21 (#342): adds --engine halmos|medusa|both. When medusa or both, also
# emits a Property_<ContractName>.t.sol harness with a Medusa-discoverable
# non-view property_placeholder() returns (bool).
#
# I22 (#344): bisected the medusa "no assertion, property, optimization, or
# custom tests were found to fuzz" failure. Two issues stacked:
#
#   (a) crytic-compile (medusa's compilation backend) skips `./test/**` by
#       default via `forge build --skip ./test/**`, so harnesses placed in the
#       Foundry test directory are silently dropped from the build artifacts
#       even when --target-contracts names them. tools/fuzz-runner.sh works
#       around this by passing `--compilation-target <PROP_FILE>` directly to
#       medusa whenever it auto-resolved a Property_<X>.t.sol harness.
#
#   (b) `function property_placeholder() public view returns (bool)` is
#       discoverable by medusa's property-test scanner, but produces a runtime
#       "cannot generate fuzzed call as there are no methods to call" error
#       because no state-mutating method exists on the contract. The smallest
#       shape that medusa (1.5.x) actually fuzzes is:
#
#           contract Property_<X> is Test {
#               uint256 internal _medusaRuns;
#               function setUp() public {}
#               function property_placeholder() external returns (bool) {
#                   _medusaRuns++;
#                   return true;
#               }
#           }
#
#       Drop `view` and add a state-mutating side-effect so medusa's call
#       generator has a target. `external` (vs `public`) is not strictly
#       required for discovery, but matches the shape medusa's docs lead with
#       and avoids an inherited-Test name collision. End-to-end coverage lives
#       in tools/tests/test_audit_deep_scaffold.sh::test_medusa_discovers_*.
#
# Supported classes:
#   erc20 | erc4626 | erc7540 | exchange | lending | amm | bridge | staking | generic
#
# Usage:
#   ./tools/gen-invariants.sh <contract-path> <workspace> \
#     [--class <name>] [--brief-file out.md] [--engine halmos|medusa|both]
#
# Output: (a) harness at <resolved-test-dir>/Invariant_<ContractName>.t.sol
#             (and optionally Property_<ContractName>.t.sol)
#         (b) brief to stdout or --brief-file
#         (c) on stderr: `[gen-invariants] class=<detected-or-given> engine=<engine>`

set -u
CONTRACT="${1:-}"
WS="${2:-}"
BRIEF_FILE=""
CLASS=""
ENGINE="halmos"
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --brief-file) BRIEF_FILE="$2"; shift 2 ;;
    --class) CLASS="$2"; shift 2 ;;
    --engine) ENGINE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$CONTRACT" ] || [ ! -f "$CONTRACT" ] || [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <contract.sol> <workspace-dir> [--class <name>] [--brief-file out.md] [--engine halmos|medusa|both]" >&2
  echo "classes: erc20 erc4626 erc7540 exchange lending amm bridge staking generic" >&2
  exit 2
fi

case "$ENGINE" in
  halmos|medusa|both) ;;
  *) echo "[gen-invariants] invalid --engine '$ENGINE' (expected halmos|medusa|both)" >&2; exit 2 ;;
esac

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_NAME=$(basename "$CONTRACT" .sol)
TEMPLATES="$AUDITOOOR_DIR/reference/invariant_templates.yaml"
CLASS_DIR="$AUDITOOOR_DIR/reference/invariant_class_templates"

# I20: resolve test directory from foundry.toml (default test/)
RESOLVED_TEST_DIR="test"
if command -v python3 >/dev/null 2>&1; then
  RESOLVED_TEST_DIR="$(python3 "$AUDITOOOR_DIR/tools/lib/resolve-forge-test-dir.py" "$WS" 2>/dev/null || echo test)"
fi

HARNESS_DIR="$WS/$RESOLVED_TEST_DIR"
HARNESS_FILE="$HARNESS_DIR/Invariant_${CONTRACT_NAME}.t.sol"
PROPERTY_FILE="$HARNESS_DIR/Property_${CONTRACT_NAME}.t.sol"

mkdir -p "$HARNESS_DIR"

# ---- class auto-detection -------------------------------------------------
# Grep the source for class-signature functions. First match wins.
detect_class() {
  local src="$1"
  # ERC-7540 async vault: requestDeposit(uint256,address,address) -> uint256
  if grep -Eq 'function[[:space:]]+requestDeposit[[:space:]]*\(' "$src"; then
    echo erc7540; return
  fi
  # ERC-4626: deposit(uint256 assets, address receiver) + asset() + totalAssets()
  if grep -Eq 'function[[:space:]]+deposit[[:space:]]*\([[:space:]]*uint256[[:space:]]+assets' "$src" \
     || { grep -Eq 'function[[:space:]]+totalAssets[[:space:]]*\(' "$src" \
          && grep -Eq 'function[[:space:]]+convertToShares[[:space:]]*\(' "$src"; }; then
    echo erc4626; return
  fi
  # Exchange / CLOB: matchOrders, fillOrder, orderStatus
  if grep -Eq 'function[[:space:]]+(matchOrders|fillOrder|fillOrders|cancelOrder)[[:space:]]*\(' "$src" \
     || grep -Eq 'orderStatus|OrderStatus' "$src"; then
    echo exchange; return
  fi
  # AMM: swap, addLiquidity, getReserves
  if grep -Eq 'function[[:space:]]+(swap|addLiquidity|getReserves)[[:space:]]*\(' "$src"; then
    echo amm; return
  fi
  # Lending: borrow + repay + liquidate / liquidationIncentive
  if grep -Eq 'function[[:space:]]+(borrow|repay|liquidate)[[:space:]]*\(' "$src" \
     || grep -Eq 'liquidationIncentive|borrowIndex|utilization' "$src"; then
    echo lending; return
  fi
  # Bridge: sendMessage / lzReceive / outboundNonce
  if grep -Eq 'function[[:space:]]+(sendMessage|lzReceive|receiveMessage)[[:space:]]*\(' "$src" \
     || grep -Eq 'outboundNonce|inboundNonce|dstChainId|srcChainId' "$src"; then
    echo bridge; return
  fi
  # Staking: stake + withdraw + getReward / earned
  if grep -Eq 'function[[:space:]]+(stake|unstake|getReward|claimReward)[[:space:]]*\(' "$src" \
     || grep -Eq 'rewardPerToken|earned[[:space:]]*\(' "$src"; then
    echo staking; return
  fi
  # ERC-20: transfer + balanceOf + totalSupply + approve
  if grep -Eq 'function[[:space:]]+transfer[[:space:]]*\(' "$src" \
     && grep -Eq 'function[[:space:]]+approve[[:space:]]*\(' "$src" \
     && grep -Eq 'function[[:space:]]+balanceOf[[:space:]]*\(' "$src"; then
    echo erc20; return
  fi
  echo generic
}

if [ -z "$CLASS" ]; then
  CLASS=$(detect_class "$CONTRACT")
fi

echo "[gen-invariants] class=$CLASS engine=$ENGINE" >&2

# ---- scaffold harness ------------------------------------------------------
CLASS_TEMPLATE="$CLASS_DIR/${CLASS}.sol.template"

_scaffold_invariant() {
  local out="$1"
  if [ "$CLASS" != "generic" ] && [ -f "$CLASS_TEMPLATE" ]; then
    perl -pe "s/__CONTRACT_NAME__/$CONTRACT_NAME/g; s{__CONTRACT_PATH__}{$CONTRACT}g" \
      "$CLASS_TEMPLATE" > "$out"
  else
    cat > "$out" <<EOF
// SPDX-License-Identifier: MIT
// Auto-scaffolded by tools/gen-invariants.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
// Target: $CONTRACT  (class: generic)
// TODO: agent fills in invariant_* functions per reference/invariant_templates.yaml
pragma solidity ^0.8.20;

import {Test, StdInvariant} from "forge-std/Test.sol";
// import {$CONTRACT_NAME} from "$CONTRACT";

contract Invariant_${CONTRACT_NAME} is StdInvariant, Test {
    // $CONTRACT_NAME public target;
    // Handler public handler;

    function setUp() public {
        // target = new $CONTRACT_NAME(...);
        // handler = new Handler(target);
        // targetContract(address(handler));
    }

    function invariant_placeholder() public view {
        // TODO: agent replaces with real invariants
        assert(true);
    }
}
EOF
  fi
}

_scaffold_property() {
  local out="$1"
  cat > "$out" <<EOF
// SPDX-License-Identifier: MIT
// Auto-scaffolded by tools/gen-invariants.sh (medusa property harness) on $(date -u +%Y-%m-%dT%H:%M:%SZ)
// Target: $CONTRACT  (class: generic)
// TODO: agent fills in property_* functions per reference/invariant_templates.yaml
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
// import {$CONTRACT_NAME} from "$CONTRACT";

contract Property_${CONTRACT_NAME} is Test {
    // $CONTRACT_NAME public target;
    uint256 internal _medusaRuns;

    function setUp() public {
        // target = new $CONTRACT_NAME(...);
    }

    function property_placeholder() external returns (bool) {
        // TODO: agent replaces with real property checks
        // Mutating a tiny counter keeps Medusa's call generator engaged even
        // before a real handler/target is wired into this scaffold.
        _medusaRuns++;
        return true;
    }
}
EOF
}

# Invariant scaffold (halmos / forge invariant convention)
if [ ! -f "$HARNESS_FILE" ]; then
  _scaffold_invariant "$HARNESS_FILE"
  echo "[gen-invariants] wrote $HARNESS_FILE (class=$CLASS)" >&2
else
  echo "[gen-invariants] reuse existing $HARNESS_FILE" >&2
fi

# Property scaffold (medusa convention)
if [ "$ENGINE" = "medusa" ] || [ "$ENGINE" = "both" ]; then
  if [ ! -f "$PROPERTY_FILE" ]; then
    _scaffold_property "$PROPERTY_FILE"
    echo "[gen-invariants] wrote $PROPERTY_FILE (medusa property harness)" >&2
  else
    echo "[gen-invariants] reuse existing $PROPERTY_FILE" >&2
  fi
fi

# ---- build agent brief -----------------------------------------------------
write() {
  if [ -n "$BRIEF_FILE" ]; then echo "$@" >> "$BRIEF_FILE"
  else echo "$@"
  fi
}

[ -n "$BRIEF_FILE" ] && : > "$BRIEF_FILE"

write "# Invariant harness brief — $CONTRACT_NAME (class: $CLASS)"
write ""
write "Target: \`$CONTRACT\`"
write "Workspace: \`$WS\`"
write "Test dir: \`$HARNESS_DIR\`"
write "Invariant harness: \`$HARNESS_FILE\`"
if [ "$ENGINE" = "medusa" ] || [ "$ENGINE" = "both" ]; then
  write "Property harness: \`$PROPERTY_FILE\`"
fi
write "Detected/chosen class: **$CLASS**"
write ""
write "## Task"
write ""
write "Finish the scaffolded Foundry invariant harness. The class template ships"
write "with 3-5 canonical invariants already written for this contract class."
write "Your job:"
write ""
write "1. Wire \`setUp()\` to construct the real target (uncomment the \`new\` call,"
write "   pass real ctor args). Adjust the \`I*Like\` interface if the target"
write "   names functions differently."
write "2. Extend the Handler with mutators that actually hit your target's surface."
write "3. Add 2-5 more \`invariant_\`* specific to the target's business logic"
write "   (read reference/invariant_templates.yaml for the full palette)."
if [ "$ENGINE" = "medusa" ] || [ "$ENGINE" = "both" ]; then
  write "4. For medusa: add 2-5 \`property_\`* functions returning \`bool\` that"
  write "   encode the same invariants in medusa's property-test convention."
fi
write ""
write "## Class-specific canonical invariants already scaffolded"
write ""
case "$CLASS" in
  erc20)    write "- totalSupply conservation (sum(balances) <= totalSupply)"
            write "- balance-not-above-supply"
            write "- allowance upper-bound" ;;
  erc4626)  write "- share_price monotone (no decrease outside fee accrual)"
            write "- previewDeposit matches actual round-trip"
            write "- totalAssets covers sum-of-shares"
            write "- deposit/redeem roundtrip within 1 wei" ;;
  erc7540)  write "- request lifecycle monotone (claimed <= fulfilled <= requested)"
            write "- claim never exceeds fulfilled" ;;
  exchange) write "- order status one-way (no transitions back)"
            write "- fee bounded by maxFeeRateBps * volume"
            write "- collateral conservation (balance == credits - debits)"
            write "- filled order has zero remaining" ;;
  lending)  write "- solvency (totalAssets >= totalLiabilities)"
            write "- borrowIndex monotone"
            write "- liquidation incentive bounded"
            write "- utilization bounded by 100%"
            write "- borrows <= totalAssets" ;;
  amm)      write "- k non-decreasing (x*y >= k)"
            write "- reserves non-zero when pool has liquidity"
            write "- fee bounded by max" ;;
  bridge)   write "- outbound nonce monotone per dstChain"
            write "- inbound nonce monotone per srcChain"
            write "- inbound value <= outbound value (no phantom mint)" ;;
  staking)  write "- stake conservation (sum == totalStaked)"
            write "- reward conservation (distributed <= funded)"
            write "- rewardPerToken monotone"
            write "- earned bounded by funded headroom" ;;
  generic)  write "- (generic placeholder — see reference/invariant_templates.yaml)" ;;
esac
write ""
write "## Full canonical palette"
write ""
if [ -f "$TEMPLATES" ]; then
  write "\`\`\`yaml"
  cat "$TEMPLATES" >> "${BRIEF_FILE:-/dev/stdout}"
  write "\`\`\`"
fi
write ""
write "## Source (first 300 lines)"
write ""
write "\`\`\`solidity"
head -300 "$CONTRACT" >> "${BRIEF_FILE:-/dev/stdout}"
write "\`\`\`"
write ""
write "## Harness as generated"
write ""
write "\`\`\`solidity"
cat "$HARNESS_FILE" >> "${BRIEF_FILE:-/dev/stdout}"
write "\`\`\`"
write ""
write "## Run check"
write ""
write "\`forge test --invariant --match-path $HARNESS_FILE\`"
if [ "$ENGINE" = "medusa" ] || [ "$ENGINE" = "both" ]; then
  write ""
  write "## Medusa run check"
  write ""
  write "\`medusa fuzz --target-contracts Property_$CONTRACT_NAME\`"
fi
write ""

if [ -n "$BRIEF_FILE" ]; then
  echo "[gen-invariants] wrote $BRIEF_FILE + $HARNESS_FILE (class=$CLASS engine=$ENGINE)" >&2
fi
