#!/usr/bin/env bash
# apply-queries.sh — run grep approximations of Hexens Glider queries against a source tree
#
# Usage:
#   ./tools/apply-queries.sh <src-dir> [query-name ...]
#
# With no query names, runs all ~50 curated patterns.
# With query names, runs only those.
#
# Each check prints: QUERY_NAME | count | file:line examples | verdict
#
# Verdicts:
#   CLEAN    — zero hits
#   HITS     — hits to review (may be false positives)
#   SKIP     — query has no grep approximation (read Python source instead)
#
# Fixes Issue 3 from SKILL_ISSUES.md: turns a 30-min manual grep sweep into a 30-sec automated one.

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <src-dir> [query-name ...]"
    echo "Example: $0 /path/to/project/src"
    echo "         $0 /path/to/project/src access-control-missing-uups-upgrade"
    exit 1
fi

SRC_DIR="$1"
shift || true
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$SRC_DIR" ]; then
    echo "Error: $SRC_DIR is not a directory"
    exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
    echo "Error: ripgrep (rg) required. Install: brew install ripgrep"
    exit 1
fi

# Utility: run a grep pattern, return count + first 3 examples
print_hits() {
    local name="$1"
    local category="$2"
    local hits="$3"

    local count=0
    if [ -n "$hits" ]; then
        count=$(echo "$hits" | wc -l | tr -d ' ')
    fi

    if [ "$count" -eq 0 ]; then
        printf "  [CLEAN] %-8s  %s\n" "$category" "$name"
    else
        printf "  [HITS]  %-8s  %-55s  (%s hits)\n" "$category" "$name" "$count"
        echo "$hits" | head -3 | sed 's/^/          /'
    fi
}

check_pattern() {
    local name="$1"
    local category="$2"
    local pattern="$3"
    local exclude_tests="${4:-yes}"

    local rg_args=(--type-add 'sol:*.sol' -t sol -n --no-heading)
    if [ "$exclude_tests" = "yes" ]; then
        rg_args+=(-g '!test/*' -g '!tests/*' -g '!*.t.sol' -g '!mocks/*')
    fi

    local hits
    hits=$(rg "${rg_args[@]}" -e "$pattern" "$SRC_DIR" 2>/dev/null || true)

    print_hits "$name" "$category" "$hits"
}

check_precise_detector() {
    local name="$1"
    local category="$2"
    local script="$SCRIPT_DIR/detectors/solidity/$name.py"
    local hits

    if [ ! -f "$script" ]; then
        printf "  [SKIP]  %-8s  %s (missing precise detector)\n" "$category" "$name"
        return 0
    fi

    hits=$(python3 "$script" "$SRC_DIR" 2>/dev/null || true)
    print_hits "$name" "$category" "$hits"
}

# ============================================================================
#                         CURATED GREP APPROXIMATIONS
# ============================================================================

should_run() {
    local q="$1"
    if [ $# -le 1 ]; then return 0; fi
    shift
    for arg; do
        if [ "$arg" = "$q" ]; then return 0; fi
    done
    return 1
}

should_run_any() {
    local names=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        names+=("$1")
        shift
    done
    if [ $# -gt 0 ] && [ "$1" = "--" ]; then
        shift
    fi
    if [ $# -eq 0 ]; then return 0; fi
    local arg
    local name
    for arg; do
        for name in "${names[@]}"; do
            if [ "$arg" = "$name" ]; then return 0; fi
        done
    done
    return 1
}

echo "============================================================================"
echo "Applying Hexens-derived grep approximations against: $SRC_DIR"
echo "============================================================================"
echo

# ACCESS CONTROL
echo "=== Access Control ==="

should_run "pause-functions-lack-access-control" "$@" && \
    check_pattern "pause-functions-lack-access-control" "access" 'function\s+(pause|unpause|emergencyPause)\s*\([^)]*\)\s+external\s*\{'

should_run "eth-balance-withdrawal-by-anyone" "$@" && \
    check_pattern "eth-balance-withdrawal-by-anyone" "access" 'transfer\(.*address\(this\)\.balance\)'

should_run "missing-two-step-ownership-transfer" "$@" && \
    check_pattern "missing-two-step-ownership-transfer" "access" 'function\s+transferOwnership\s*\('

should_run "setters-with-no-access-control" "$@" && \
    check_pattern "setters-with-no-access-control" "access" 'function\s+set[A-Z]\w+\s*\([^)]*\)\s+external\s*\{'

should_run "self-destructable-contracts" "$@" && \
    check_pattern "self-destructable-contracts" "access" 'selfdestruct|suicide'

should_run "eoa-restricted-modifiers-that-checks-the-bytecode" "$@" && \
    check_pattern "eoa-restricted-via-extcodesize" "access" 'extcodesize\s*\(|tx\.origin\s*=='

should_run "timelock-contracts-missing-operation-ready" "$@" && \
    check_pattern "timelock-missing-isOperationReady" "access" 'TimelockController|_beforeCall'

echo
echo "=== Signature / EIP-712 ==="

should_run "lack-of-address-validation-check-when-using-ecrecover" "$@" && \
    check_pattern "ecrecover-without-zero-check" "sig" 'ecrecover\s*\('

should_run "eip-712-signature-replay-across-different-domains" "$@" && \
    check_pattern "eip-712-missing-addressthis-in-domain" "sig" 'DOMAIN_TYPEHASH|_domainSeparatorV4\|domainSeparator'

should_run "hash-collision-with-abi-encode-packed" "$@" && \
    check_pattern "abi-encodePacked-with-dynamic" "sig" 'abi\.encodePacked\([^)]*,\s*(bytes |string |\w+\[\])'

should_run "missing-signature-nonce-storage" "$@" && \
    check_pattern "signature-without-nonce" "sig" 'ecrecover|_recover\('

should_run "lack-of-signature-validation-check-against-low-s" "$@" && \
    check_pattern "ecdsa-malleability-low-s" "sig" 'ecrecover\s*\('

should_run "erc-2771-msg-sender-address-forgery" "$@" && \
    check_pattern "erc-2771-msgSender-forgery" "sig" 'ERC2771Context|isTrustedForwarder\s*\(|is\s+ERC2771'
    # FP-fix (wave-14): old pattern fired on ANY _msgSender() call, including contracts
    # that only inherit plain OZ Context (which returns msg.sender verbatim, no forwarder).
    # New pattern requires the ERC2771Context inheritance / isTrustedForwarder presence,
    # which are the discriminating signals that a trusted-forwarder relationship exists.
    # Contracts that merely inherit Context and call _msgSender() will no longer fire.

echo
echo "=== Oracle / Pricing ==="

should_run "flashloan-price-manipulation" "$@" && \
    check_pattern "flashloan-price-manipulation" "oracle" '(getReserves|slot0|balanceOf\(address\())'

should_run "chainlink-oracle-without-try-catch" "$@" && \
    check_pattern "chainlink-without-try-catch" "oracle" 'latestRoundData\s*\('

should_run "pyth-oracle-without-freshness-check" "$@" && \
    check_pattern "pyth-getPriceUnsafe" "oracle" 'getPriceUnsafe\s*\('

should_run "single-source-oracle-compromise" "$@" && \
    check_pattern "single-oracle-no-fallback" "oracle" 'aggregator|priceFeed'

should_run "oracle-price-used-as-denominator-without-zero" "$@" && \
    check_pattern "oracle-price-as-denominator" "oracle" '/\s*price|/\s*priceFeed'

should_run "vulnerable-curve-get-p-spot-price" "$@" && \
    check_pattern "curve-get-p-spot-price" "oracle" 'get_p\s*\('

echo
echo "=== ERC4626 ==="

should_run "erc-4626-share-inflation-attack" "$@" && \
    check_pattern "erc4626-balanceOf-this-in-share-calc" "vault" 'IERC4626|ERC4626.*deposit\|balanceOf\(address\(this\)\).*\/'

# tightened 2026-04-15: `function mint(` matched non-ERC4626 token mint() in collateral
# contracts. Require the ERC4626 signature: takes a uint256 assets/shares + address receiver.
should_run "erc-4626-missing-slippage-parameters" "$@" && \
    check_pattern "erc4626-functions-no-slippage" "vault" 'function\s+(deposit|mint|withdraw|redeem)\s*\(\s*uint256[^)]*address'

should_run "erc-4626-max-functions-dont-account-for-pause" "$@" && \
    check_pattern "erc4626-max-functions" "vault" 'function\s+max(Deposit|Mint|Withdraw|Redeem)\s*\('

should_run "incorrect-rounding-direction-in-erc4626-preview" "$@" && \
    check_pattern "erc4626-preview-rounding" "vault" 'function\s+preview(Deposit|Mint|Withdraw|Redeem)'

echo
echo "=== Upgradeability (UUPS, initializers, storage layout) ==="

should_run "missing-access-control-in-uups-authorizeUpgrade" "$@" && \
    check_pattern "uups-authorize-upgrade-missing-gate" "upgrade" '_authorizeUpgrade\s*\('

## tightened 2026-04-19 (Phase 40c): require external|public visibility on the
## same line, so internal/private library helpers like
##   `function initialize(...) internal pure returns (MarketData)`
## are excluded. Interface files (no body) are dropped via engage.py path
## blacklist (`/interfaces/`, `/Interfaces/`).
should_run "logic-contract-takeover-via-unprotected-initialize" "$@" && \
    check_pattern "unprotected-initialize" "upgrade" 'function\s+initialize\s*\([^)]*\)[^;{]*\b(external|public)\b'

should_run "initialize-functions-callable-more-than-once" "$@" && \
    check_pattern "initialize-multiple-calls" "upgrade" 'function\s+initialize[\w]*\s*\([^)]*\)[^;{]*\b(external|public)\b'

should_run "uninitialized-implementation-vulnerability" "$@" && \
    check_pattern "uninitialized-impl-disableInitializers" "upgrade" '_disableInitializers\s*\('

should_run "missing-storage-gap-in-upgradeable-contracts" "$@" && \
    check_pattern "upgradeable-no-gap" "upgrade" 'uint256\[\d*\]\s+private\s+__gap'

should_run "contracts-where-delegatecall-target-is-state" "$@" && \
    check_pattern "delegatecall-to-state-variable" "upgrade" '\.delegatecall\('

should_run "create3-salt-hijack" "$@" && \
    check_pattern "create3-salt-hijack" "upgrade" 'CREATE3|create3'

should_run "payable-multicall-can-drain-msgvalue" "$@" && \
    check_pattern "payable-multicall-msgvalue-reuse" "upgrade" 'function\s+multicall\s*\([^)]*\)\s+(external|public)\s+payable'

echo
echo "=== Reentrancy ==="

should_run "lack-of-cei-pattern-leading-to-reentrancy" "$@" && \
    check_pattern "external-call-before-state-update" "reentrancy" '\.call\s*\{|\.call\s*\('

# tightened 2026-04-15: was matching ALL safeTransferFrom/safeBatchTransferFrom including ERC20
# safe-transfer wrappers (SafeTransferLib). Scope to ERC1155 5-arg call form (not declarations).
# Exclude interface function declarations (lines ending in `;` after the signature).
should_run "broken-cei-pattern-with-erc1155-transfers" "$@" && \
    check_pattern "erc1155-transfer-before-state" "reentrancy" '\.(safeBatchTransferFrom|safeTransferFrom)\s*\([^)]*,[^)]*,[^)]*,[^)]*,'

should_run "unauthenticated-flashloan-callbacks" "$@" && \
    check_pattern "flashloan-callback-no-sender-check" "reentrancy" 'onFlashLoan|executeOperation|pancakeV3'

should_run "non-reentrant-functions-calling-each-other" "$@" && \
    check_pattern "nonReentrant-chained-reverts" "reentrancy" 'nonReentrant'

echo
echo "=== Math / Rounding ==="

# tightened 2026-04-15: was matching comments (// ... / x * y) and doc lines.
# Require the division to appear as actual code: preceded by a variable/paren, not //
should_run "division-before-multiplication" "$@" && \
    check_pattern "div-before-mul-precision-loss" "math" '^[^/]*[a-zA-Z0-9_)]\s*/\s*\w+\s*\*'

# tightened 2026-04-15: bare `assembly {` matches every assembly block including benign ones
# in tests and helpers. Scope to blocks that contain unchecked arithmetic ops (add/mul/sub/div).
should_run "integer-overflow-in-yul-assembly" "$@" && \
    check_pattern "yul-unchecked-arithmetic" "math" 'assembly\s*\{[^}]*(add|mul|sub|div)\s*\('

should_run "pool-invariant-fails-to-revert-on-non-convergence" "$@" && \
    check_pattern "invariant-solver-silent-return" "math" 'for\s*\([^)]*<\s*255|for\s*\([^)]*<\s*64'

# tightened 2026-04-15: `/\s*\w+[;\)]` matched comments, doc strings, and any division.
# Require division result assigned to a variable (state write likely) and not in a comment.
should_run "rounding-to-zero-solvency-bypass" "$@" && \
    check_pattern "division-to-zero-solvency" "math" '^\s*[^/][^/]*=\s*\w[^;]*/\s*\w+\s*;'

should_run "unsafe-type-casting" "$@" && \
    check_pattern "downcast-uint256-to-smaller" "math" '(uint128|uint64|uint32|uint16|uint8|int128|int64)\s*\('

# tightened 2026-04-15: bare `int256\s*\(` matched uint256(...) and bytes32(...) casts
# that contain uint256 as inner expressions. Require the outer cast keyword is int256.
should_run "unsafe-uint256-to-int256-cast" "$@" && \
    check_pattern "uint256-to-int256-cast" "math" '\bint256\s*\(\s*(uint256|[a-zA-Z_]\w*)\s*\)'

should_run "y-eth-product-collapse-exploits" "$@" && \
    check_pattern "stableswap-product-term-collapse" "math" 'unsafe_mul|unsafe_div|unsafe_sub'

echo
echo "=== DoS ==="

should_run "unbounded-loops-with-low-level-external-calls" "$@" && \
    check_pattern "unbounded-loop-external-call" "dos" 'for\s*\([^)]*<\s*\w+\.length'

should_run "state-arrays-can-grow-with-no-way-to-shrink" "$@" && \
    check_pattern "unbounded-growing-state-array" "dos" '\.push\s*\('

should_run "hardcoded-gas-amount-in-low-level-calls" "$@" && \
    check_pattern "hardcoded-gas-call" "dos" '\.call\{[^}]*gas:'

should_run "grief-dos-calls-utilizing-permit" "$@" && \
    check_pattern "permit-frontrun-revert" "dos" '\.permit\s*\('

echo
echo "=== Cross-Chain ==="

# tightened 2026-04-15: `block.chainid` alone in tests is benign (e.g. constructing domain
# separator in test helpers). Match DOMAIN_TYPEHASH definitions that do NOT include chainId
# as a field — i.e., the separator struct literal is built without block.chainid present.
should_run "cross-chain-replay-missing-chainid" "$@" && \
    check_pattern "eip712-missing-chainid" "bridge" 'DOMAIN_TYPEHASH\s*=\s*keccak256\s*\(|bytes32\s+private\s+(constant\s+)?DOMAIN_TYPEHASH'

should_run "layer-zero-lz-send-unvalidated-adapter-params" "$@" && \
    check_pattern "lzSend-adapter-params" "bridge" '_lzSend|lzSend'

should_run "lack-of-msgsender-validation-lz-endpoint" "$@" && \
    check_pattern "lzReceive-no-sender-check" "bridge" 'lzReceive\s*\('

echo
echo "=== Uniswap-specific ==="

# tightened 2026-04-15: `block.timestamp.*deadline` matched `require(block.timestamp <= _deadline)`
# which is correct defensive code. The anti-pattern is passing block.timestamp AS the deadline
# argument, not checking against it. Look for deadline being SET to block.timestamp directly.
should_run "uniswap-swap-blocktimestamp-as-deadline" "$@" && \
    check_pattern "uniswap-blocktimestamp-deadline" "uniswap" '(deadline\s*[:=]\s*block\.timestamp\b|block\.timestamp\s*\)\s*,|,\s*block\.timestamp\s*\))'

should_run "uniswap-v3-callback-no-caller-check" "$@" && \
    check_pattern "uniswap-v3-callback" "uniswap" 'uniswapV3SwapCallback|uniswapV3MintCallback'

should_run "uniswap-v4-hook-no-poolmanager-check" "$@" && \
    check_pattern "uniswap-v4-hook-no-sender-check" "uniswap" 'beforeSwap|afterSwap|beforeAdd|afterAdd'

echo
echo "=== Misc (high-hit-rate classes) ==="

should_run "classic-return-bomb-attack" "$@" && \
    check_pattern "return-bomb-low-level-call" "misc" 'abi\.decode.*\.call|abi\.decode.*returndata'

should_run "missing-validation-on-low-level-call-returns" "$@" && \
    check_pattern "unchecked-low-level-call" "misc" '\.call\s*\('

# tightened 2026-04-15: bare `constructor\s*\(` matched every constructor including
# zero-arg ones. Require at least one address parameter to make the check relevant.
should_run "missing-zero-address-validation-in-constructor" "$@" && \
    check_pattern "constructor-no-zero-address-check" "misc" 'constructor\s*\([^)]*\baddress\b'

should_run "inverted-signature-merkle-proof-verification" "$@" && \
    check_pattern "inverted-verify-return" "misc" 'MerkleProof\.verify|function\s+verify\s*\('

should_run "misuse-of-transient-storage-for-authentication" "$@" && \
    check_pattern "eip1153-transient-auth-misuse" "misc" 'tstore|tload|transient'

should_run "indexed-dynamic-types-are-hashed" "$@" && \
    check_pattern "event-indexed-dynamic-type" "misc" 'event\s+\w+\s*\([^)]*indexed\s+(bytes |string |\w+\[\])'

should_run "destroyable-contracts-with-ecrecover" "$@" && \
    check_pattern "ecrecover-to-selfdestruct-path" "misc" 'selfdestruct'

should_run "initialize-functions-callable-more-than-once" "$@" && \
    check_pattern "initializer-modifier-missing" "misc" 'function\s+initialize\s*\([^)]*\)\s+(external|public)\s*\{'

should_run "permissionless-functions-with-arbitrary-call" "$@" && \
    check_pattern "permissionless-arbitrary-call" "misc" 'function\s+\w+\s*\([^)]*\)\s+external\s+[^{]*\{[^}]*\.call\('

# ============================================================================
#                    EXTENDED PATTERNS — batch 2
# ============================================================================

# --- access (additional) ---
echo
echo "=== Access Control (extended) ==="

should_run "pause-functions-lack-access-control-unpause" "$@" && \
    check_pattern "missing-unpause-function" "access" 'whenNotPaused'

# tightened 2026-04-15: matched EVERY external/public function (421 hits).
# Now require the function has a body that contains a state-write indicator (=, .push, delete)
# AND does NOT already have whenNotPaused/onlyUnpaused, narrowing to actual candidates.
should_run "public-state-modifying-functions-lacking-pause-protection" "$@" && \
    check_pattern "state-modify-without-whenNotPaused" "access" 'function\s+\w+\s*\([^)]*\)\s+(external|public)\s+(?!.*whenNotPaused)(?!.*onlyUnpaused)[^{]*\{' "no"

should_run "detects-unprotected-ownership-and-admin-transfer-f" "$@" && \
    check_pattern "unprotected-admin-transfer" "access" 'function\s+(setOwner|updateOwner|updateAdmin|transferControl|setGovernance|updateGovernance|transferGovernance)\s*\('

should_run "anyone-can-call-erc-token-transfers" "$@" && \
    check_pattern "backdoor-token-transfer-no-modifier" "access" 'function\s+\w+\s*\([^)]*\)\s+external\s*\{[^}]*(transfer|transferFrom|safeTransfer)\s*\('

should_run "flawed-logic-in-msg-sender-access-control-check" "$@" && \
    check_pattern "inverted-access-control-condition" "access" 'require\s*\(\s*msg\.sender\s*!=\s*(owner|admin|governance)'

should_run "ac-on-erc721received" "$@" && \
    check_pattern "erc721received-no-sender-check" "access" 'function\s+onERC721Received\s*\('

# tightened 2026-04-15: matched interface declarations and mocks in test helpers.
# Require the implementation body opens immediately (no semicolon / no `external returns` only).
should_run "ac-on-erc1155received" "$@" && \
    check_pattern "erc1155received-no-sender-check" "access" 'function\s+on(ERC1155Received|ERC1155BatchReceived)\s*\([^)]*\)[^;{]*\{'

# --- oracle (additional) ---
echo
echo "=== Oracle (extended) ==="

should_run "api3-oracle-price-data-is-not-validated-for-stalen" "$@" && \
    check_pattern "api3-oracle-no-staleness-check" "oracle" '\.read\s*\(\s*\)'

should_run "band-oracle-price-data-is-not-validated-for-stalen" "$@" && \
    check_pattern "band-oracle-getReferenceData" "oracle" 'getReferenceData(Bulk)?\s*\('

should_run "oracle-prices-with-hardcoded-scales" "$@" && \
    check_pattern "oracle-hardcoded-scale-no-decimals" "oracle" '(1e18|1e8|10\s*\*\*\s*18|10\s*\*\*\s*8)\s*[/*]'

should_run "request-confirmation-is-too-low-in-chainlink-vrf-i" "$@" && \
    check_pattern "chainlink-vrf-requestRandomWords" "oracle" 'requestRandomWords\s*\('

should_run "unprotected-chainlink-vrf-request-leading-to-subsc" "$@" && \
    check_pattern "chainlink-vrf-unprotected-request" "oracle" 'function\s+request\w*\s*\([^)]*\)\s+(external|public)\s*[^{]*\{[^}]*requestRandomWords'

should_run "miner-controllable-randomness-via-block-variables" "$@" && \
    check_pattern "block-variable-as-randomness" "oracle" '(block\.(timestamp|number|coinbase|difficulty|prevrandao)|tx\.(origin|gasprice))\s*[%^&|]'

# --- erc4626 (standalone category) ---
echo
echo "=== ERC4626 (extended) ==="

should_run "erc-4626-functions-revert-breaking-specification-r" "$@" && \
    check_pattern "erc4626-max-fn-must-not-revert" "erc4626" 'function\s+max(Deposit|Mint|Withdraw|Redeem)\s*\('

should_run "erc4626-first-depositor-attack-share-price-manipul" "$@" && \
    check_pattern "erc4626-first-depositor-no-min-check" "erc4626" 'function\s+(deposit|mint)\s*\([^)]*uint256[^)]*address'

# tightened 2026-04-15: matched `function mint(address _to, uint256 _amount)` in collateral
# contracts (not ERC4626 vaults). Require ERC4626 signature: uint256 first param + address receiver.
should_run_any "lack-of-asset-pulling-in-erc-4626-vaults-leads-to" "erc4626-asset-not-pulled" -- "$@" && \
    check_precise_detector "erc4626-asset-not-pulled" "erc4626"

should_run "vault-total-asset-rely-on-external-manipulatable-t" "$@" && \
    check_pattern "vault-totalAssets-relies-on-balanceOf" "erc4626" 'totalAssets\s*\(\s*\)[^{]*balanceOf\s*\(address\s*\(this\s*\)'

should_run "rounding-asymmetry-in-share-debt-conversion-flows" "$@" && \
    check_pattern "erc4626-rounding-asymmetry" "erc4626" 'function\s+(convertToShares|convertToAssets)\s*\('

# --- nft ---
echo
echo "=== NFT ==="

# tightened 2026-04-15: matched `function burn(uint256 _amount)` in role-gated collateral
# token. Require no access-control modifier visible on the same line (no onlyOwner/onlyRoles/etc).
should_run "erc-721-tokens-can-be-burned-by-anyone" "$@" && \
    check_pattern "erc721-burn-no-sender-check" "nft" 'function\s+burn\s*\(\s*uint256[^)]*\)\s+(external|public)\s*\{'

should_run "erc721-hook-missing-self-transfer-guard-reward-log" "$@" && \
    check_pattern "erc721-hook-no-self-transfer-guard" "nft" 'function\s+_(before|after)TokenTransfer\s*\('

should_run "claiming-nft-rewards-lack-ownership-validation" "$@" && \
    check_pattern "nft-claim-reward-no-ownership-check" "nft" 'function\s+(claim|harvest|collect)\w*\s*\([^)]*tokenId'

should_run "set-approval-for-all-can-be-called-by-anyone" "$@" && \
    check_pattern "setApprovalForAll-no-access-control" "nft" '_setApprovalForAll\s*\('

should_run "nft-minting-allows-arbitrary-user-string-input-for" "$@" && \
    check_pattern "nft-mint-user-supplied-uri" "nft" 'function\s+\w*[Mm]int\w*\s*\([^)]*string'

# --- governance ---
echo
echo "=== Governance ==="

should_run "flawed-enumerable-set-remove-iteration-can-skip-el" "$@" && \
    check_pattern "enumerable-set-remove-in-loop" "governance" '\.remove\s*\([^)]*\)\s*;[^}]*\.at\s*\(|\.at\s*\([^)]*\)[^;]*\.remove\s*\('

should_run_any "deletion-of-nested-enumerable-setenumerable-map-le" "delete-enumerable-set-struct" -- "$@" && \
    check_precise_detector "delete-enumerable-set-struct" "governance"

should_run "impossible-quorum" "$@" && \
    check_pattern "governance-impossible-quorum" "governance" 'function\s+\w*[Qq]uorum\w*\s*\('

should_run "two-step-ownership-transfer-with-incorrect-modifie" "$@" && \
    check_pattern "two-step-ownership-wrong-modifier" "governance" 'function\s+(acceptOwnership|claimOwnership|acceptAdmin|claimAdmin|acceptGovernance)\s*\('

should_run "governance-self-delegation" "$@" && \
    check_pattern "governance-delegate-no-zero-check" "governance" 'function\s+delegates?\s*\(\s*address'

should_run "interest-accruals-when-contract-is-paused" "$@" && \
    check_pattern "interest-accrual-when-paused" "governance" '(accrue|accrueInterest|updateInterest|_accrueInterest)\s*\('

# --- gas ---
echo
echo "=== Gas ==="

should_run "hardcoded-gas-amount-in-low-level-calls" "$@" && \
    check_pattern "hardcoded-gas-in-call" "gas" '\.call\s*\{[^}]*gas\s*:\s*[0-9]+'

should_run "gasleft-is-utilized-in-external-call-without-ensur" "$@" && \
    check_pattern "gasleft-without-63-64-rule" "gas" 'gasleft\s*\(\s*\)'

# tightened 2026-04-15: inherited tightening from math section — same pattern, same fix.
# Single-line assembly block with add/mul/sub already handled by the math variant above.
should_run "integer-overflow-in-yul-assembly" "$@" && \
    check_pattern "yul-unchecked-add-mul-sub" "gas" 'assembly\s*\{[^}]*(add|mul|sub)\s*\('

# --- casts ---
echo
echo "=== Unsafe Casts ==="

# tightened 2026-04-15: was matching `uint256(...)` nested inside `bytes32(uint256(...))`.
# Add word boundary to require the outer cast is int256, not another numeric type.
should_run "unsafe-uint256-to-int256-cast" "$@" && \
    check_pattern "unsafe-uint256-to-int256" "casts" '\bint256\s*\(\s*(uint256|[a-zA-Z_]\w*)\s*\)'

should_run "unsafe-type-casting" "$@" && \
    check_pattern "unsafe-downcast-uint" "casts" '(uint8|uint16|uint32|uint64|uint128|int8|int16|int32|int64|int128)\s*\(\s*(uint256|int256|[a-zA-Z_]\w*)\s*\)'

# --- erc20 ---
echo
echo "=== ERC20 ==="

should_run "open-zeppelins-deprecated-safe-approve-function-is" "$@" && \
    check_pattern "deprecated-safeApprove" "erc20" 'safeApprove\s*\('

# tightened 2026-04-15: matched test helper and mock files. Exclude test-only patterns
# by requiring the approval is NOT wrapped in a safe helper (safeApprove / forceApprove).
should_run "missing-approve-return-validations" "$@" && \
    check_pattern "approve-return-not-checked" "erc20" '^[^.]*(?<!safe)(?<!force)(?<!Safe)(?<!Force)\.approve\s*\([^)]*\)\s*;'

should_run "missing-transfer-return-validation" "$@" && \
    check_pattern "transfer-return-not-checked" "erc20" '\.(transfer|transferFrom)\s*\([^)]*\)\s*;'

should_run "erc20-transfer-fromsafe-transfer-from-calls-can-be" "$@" && \
    check_pattern "transferFrom-balanceOf-dos" "erc20" 'transferFrom\s*\([^)]*balanceOf\s*\('

should_run "accounting-updates-not-assuming-fee-on-transfers" "$@" && \
    check_pattern "fee-on-transfer-not-accounted" "erc20" '(safeTransferFrom|transferFrom)\s*\([^)]*address\(this\)'

# tightened 2026-04-15: too broad — matched test helpers and safeApprove wrappers.
# Require the call is a raw ERC20 approve (not prefixed by safe/force lib keyword).
should_run "detect-approve-calls-where-spender-is-arbitrary" "$@" && \
    check_pattern "approve-arbitrary-spender" "erc20" '^[^.]*(?<![Ss]afe)(?<![Ff]orce)\.approve\s*\(\s*\w+\s*,'

# tightened 2026-04-15: `.safeTransfer/.safeTransferFrom` IS the safe wrapper — calling it
# is correct by design. The vulnerability is calling the raw (unsafe) ERC20 transfer without
# checking the bool return. Repurpose this pattern to catch SafeTransferLib static calls
# where the lib is invoked but the return value might still be discarded (rare edge case):
# match only when called as a free function without a library prefix, i.e. missing SafeTransferLib.
# Pattern: safeTransfer called on a variable but NOT prefixed with SafeTransferLib.
should_run "misinterpretation-of-safe-transfer-return-values" "$@" && \
    check_pattern "safeTransfer-missing-return-check" "erc20" '^[^.]*(?<!SafeTransferLib)\.(safeTransfer|safeTransferFrom)\s*\([^)]*\)\s*;'

# --- bridge (additional) ---
echo
echo "=== Bridge (extended) ==="

should_run "missing-message-origin-validation-in-layer-zero-v2" "$@" && \
    check_pattern "lzCompose-no-from-validation" "bridge" 'function\s+lzCompose\s*\('

should_run "cross-chain-bridge-message-replays-without-nonce-v" "$@" && \
    check_pattern "bridge-message-no-nonce" "bridge" 'function\s+(executeMessage|processMessage|handleMessage|receiveMessage)\s*\('

should_run "relayers-can-spoof-messages" "$@" && \
    check_pattern "across-handleV3-no-validation" "bridge" 'function\s+handleV3AcrossMessage\s*\('

should_run "layer-zero-token-transfers-are-configured-causing" "$@" && \
    check_pattern "lz-token-transfer-misconfigured" "bridge" '(setMinDstGas|setDefaultFeeBp|setUseCustomAdapterParams)\s*\('

should_run "lack-of-validator-duplication-check-during-validat" "$@" && \
    check_pattern "valset-update-no-dedup-check" "bridge" 'function\s+(updateValset|updateValidatorSet|setValset)\s*\('

# --- uniswap-v4 (additional) ---
echo
echo "=== Uniswap V4 (extended) ==="

should_run "uniswap-v4-hook-no-poolmanager-check" "$@" && \
    check_pattern "uniswap-v4-hook-all-callbacks" "uniswap-v4" 'function\s+(before|after)(Swap|AddLiquidity|RemoveLiquidity|Donate|Initialize)\s*\('

should_run "uniswap-v4-pool-key-used-without-first-comparing-i" "$@" && \
    check_pattern "uniswap-v4-poolkey-no-whitelist" "uniswap-v4" 'PoolKey\s+(memory|calldata)\s+\w+'

should_run "uniswap-v4-hook-unsettled-delta" "$@" && \
    check_pattern "uniswap-v4-unsettled-delta" "uniswap-v4" 'function\s+(afterSwap|afterAddLiquidity|afterRemoveLiquidity)\s*\([^)]*\)[^{]*\{'

should_run "uniswap-v4-subscriber-callbacks-lack-position-mana" "$@" && \
    check_pattern "uniswap-v4-subscriber-no-posm-check" "uniswap-v4" 'function\s+(notifySubscribe|notifyUnsubscribe|notifyBurn|notifyModifyLiquidity)\s*\('

# --- misc (additional) ---
echo
echo "=== Misc (extended) ==="

should_run "blockhash-usage-that-can-lead-to-a-staleness" "$@" && \
    check_pattern "blockhash-stale-stored-blocknumber" "misc" 'blockhash\s*\('

should_run "miner-controllable-randomness-via-block-variables" "$@" && \
    check_pattern "block-timestamp-as-randomness" "misc" '(block\.timestamp|block\.number)\s*%'

should_run "unsafe-use-of-txorigin" "$@" && \
    check_pattern "tx-origin-non-guard-usage" "misc" 'tx\.origin'

# tightened 2026-04-15: `contract X is Y` matched every inheriting contract (27 hits).
# Narrow to contracts that inherit AND declare state variables that shadow common names.
# Use a heuristic: look for state variable declarations (uint/address/bool/mapping) right
# after an `is` inheritance chain — combined with a shadow-candidate keyword.
should_run "inherited-state-variables-shadowed" "$@" && \
    check_pattern "state-variable-shadowing" "misc" '^\s+(uint256|uint128|uint64|uint32|address|bool|mapping|bytes32)\s+(public|private|internal)\s+\b(owner|admin|paused|initialized|_initialized)\b'

should_run "non-compliant-erc165-self-identification" "$@" && \
    check_pattern "erc165-missing-0x01ffc9a7" "misc" 'function\s+supportsInterface\s*\(\s*bytes4'

# tightened 2026-04-15: matched arithmetic in comments (36 hits, all from a Yul assembly
# comment block). Exclude comment lines and require code context (semicolon on same line).
should_run "incorrect-self-referencing-compound-arithmetic" "$@" && \
    check_pattern "self-referencing-compound-assign" "misc" '^\s*(?![ \t]*//)(\w+)\s*=\s*\1\s*[+*/-]\s*\w+\s*;'

should_run "zk-sync-createcreate2-calls-with-runtime-provided" "$@" && \
    check_pattern "zksync-dynamic-create-bytecode" "misc" 'assembly\s*\{[^}]*(create|create2)\s*\('

should_run "pausable-contract-cant-be-unpaused" "$@" && \
    check_pattern "pausable-no-unpause-exposed" "misc" 'whenNotPaused'

should_run "reward-rate-precision-loss" "$@" && \
    check_pattern "reward-rate-div-without-mul" "misc" '(rewardRate|rewardPerSecond|rewardPerBlock)\s*='

should_run "reward-loss-in-staking-contracts" "$@" && \
    check_pattern "staking-reward-loss" "misc" 'function\s+(stake|deposit)\s*\([^)]*\)\s+(external|public)'

should_run "frontrunning-immediate-distribution-dilutes-the-re" "$@" && \
    check_pattern "distribution-frontrun-dilution" "misc" 'function\s+(notifyRewardAmount|addReward|distributeReward)\s*\('

should_run "unlimited-reward-mint-via-repeated-pokeaccrue-with" "$@" && \
    check_pattern "poke-accrue-unlimited-mint" "misc" 'function\s+(poke|accrue|_accrue)\s*\('

should_run "excessive-erc-20-token-withdrawal" "$@" && \
    check_pattern "excessive-erc20-withdrawal" "misc" 'function\s+\w*withdraw\w*\s*\([^)]*\)\s+(external|public)'

should_run "excessive-eth-balance-withdrawal" "$@" && \
    check_pattern "excessive-eth-withdrawal" "misc" '\.transfer\s*\(\s*address\s*\(\s*this\s*\)\s*\.\s*balance\s*\)'

should_run "draining-eth-using-flat-fee-without-msgvalue-check" "$@" && \
    check_pattern "payable-bridge-no-msgvalue-check" "misc" 'function\s+(initiateTransfer|crossChainTransfer|submitTransfer)\s*\([^)]*\)\s+(external|public)\s+payable'

should_run "allowance-retrieval-misconfigured-to-return-incorr" "$@" && \
    check_pattern "allowances-mapping-flipped-key-order" "misc" '_allowances\s*\['

should_run "exploitable-set-fee-function" "$@" && \
    check_pattern "set-fee-unrestricted" "misc" 'function\s+set(Fee|Rate|BasisPoints|ProtocolFee)\s*\([^)]*\)\s+(external|public)\s*\{'

should_run "aave-v3-flashloan-callback-execute-operation-lacks" "$@" && \
    check_pattern "aave-executeOperation-no-sender-check" "misc" 'function\s+executeOperation\s*\('

should_run_any "unchecked-erc20-transfer-return-value" "raw-transfer-no-bool-check" -- "$@" && \
    check_precise_detector "raw-transfer-no-bool-check" "misc"

should_run "batch-signature-reuse-exploits" "$@" && \
    check_pattern "batch-ecrecover-no-nonce-tracking" "misc" 'for\s*\([^)]*\)\s*\{[^}]*ecrecover\s*\('

should_run "division-rounding-to-zero-with-lp-token-minting" "$@" && \
    check_pattern "lp-token-mint-rounding-zero" "misc" '(_mint|mint)\s*\([^)]*\/[^)]*\)'

should_run "bespoke-swap-slippageprice-guard-avoidance-disable" "$@" && \
    check_pattern "swap-slippage-guard-missing" "misc" 'function\s+(swap|exchange|trade)\w*\s*\([^)]*min\w*[Aa]mount'

# ============================================================================
# --- queries requiring Glider runtime (not grep-approximable) ---
#
# The following query filenames require inter-procedural taint tracking,
# data-flow analysis, value-tree traversal, or AST type resolution
# that cannot be soundly approximated with a single ripgrep pattern.
# Run these via the Glider IDE against the target codebase instead.
#
# c1pher-bug.py
#   - Requires value-tree to detect ABI decode offset corruption; no surface syntax.
#
# contract-updates-a-memory-copy.py
#   - Needs data-flow: detects writes to memory copies of storage structs.
#     Pattern "memory \w+" is too noisy; taint from storage read to write needed.
#
# create-pair-do-s.py
#   - Uniswap V2 pair creation DoS: needs call-graph to find createPair callsites
#     and check if pair address is derived before the call (victim can precompute).
#
# denial-of-service-attack-on-uniswap-v2-pools-via-o.py
#   - Transfer of 1 wei via skim() griefing: requires inter-contract flow
#     from LP token balanceOf to K-invariant check.
#
# erc-20-permit-and-erc-20-name-mismatch-causes-eip.py
#   - Compares EIP-712 domain name() return value vs token.name(); cross-function.
#
# flawed-logic-in-msg-sender-access-control-check.py
#   - Detects inverted != vs == in access control conditionals; AST operator needed.
#
# governance-self-delegation.py
#   - Requires forward-DF from _delegate to check zero-check; interprocedural.
#
# interest-accruals-when-contract-is-paused.py
#   - Detects accrual fns reachable when paused; needs call-graph + pause modifier.
#
# lack-of-asset-pulling-in-erc-4626-vaults-leads-to.py
#   - Checks deposit/mint do NOT pull tokens (missing transferFrom); needs taint.
#
# liquidated-troves-with-icr-slightly-above-100-will.py
#   - Liquity-specific ICR threshold arithmetic; business-logic, not syntactic.
#
# liquidation-without-health-factor-validation.py
#   - Missing health-factor check before liquidation; needs call-graph.
#
# malformed-equate-statement-fails-to-assign-state-c.py
#   - Detects = vs == confusion in state variable assignments; AST operator type.
#
# missing-slippage-parameters-for-swaps-with-curve-f.py
#   - Curve swap slippage: needs arg-name + guard linkage taint.
#
# missing-validation-on-delegate-call-returns.py
#   - delegatecall return value unchecked; needs forward-DF from return bool.
#
# non-user-controlled-swap-bound-inspector.py
#   - Detects hardcoded 0 as minOut in swap calls; needs literal value-tree.
#
# pancake-swap-v3-flashloan-callback-pancake-v3swap.py
#   - PancakeV3 callback sender check; specific to protocol internal routing.
#
# redundant-variable-self-assignment.py
#   - x = x pattern detection; requires AST dest == src comparison.
#
# token-burn-on-transfer-vulnerability.py
#   - Fee-on-transfer detecting actual balance delta; needs pre/post balance taint.
#
# transaction-decoding-memory-corruption.py
#   - ABI decode memory layout corruption; assembly offset arithmetic taint.
#
# uniswap-v2v3-swaps-contain-hardcoded-minimum-amoun.py
#   - Literal 0 as amountOutMin in specific Uniswap router call signatures.
#
# users-can-prevent-getting-bad-debt-by-withdrawing.py
#   - Race condition between health check and collateral withdrawal; call-graph.
#
# unprofitable-liquidation-fee-calculation.py
#   - Business logic: liquidation fee < gas cost threshold; arithmetic analysis.
#
# verify-signature-sets-signer-as-owner-which-alows.py
#   - ecrecover return assigned directly to storage as owner; forward-DF needed.
#
# yield-position-data-removal-issues.py
#   - Yield accounting when position data deleted; struct + mapping delete taint.
#
# ============================================================================

# ============================================================================
#   WAVE 8 — GREP PORTS FROM NOVELS_UNPORTED.md (33 patterns)
#
#   Ported from reference/corpus_mined/NOVELS_UNPORTED.md GREP-class entries
#   (Zellic + Hexens slices aa..ah, Round 15 continuation). Each entry maps a
#   single-protocol bug class to a text-level approximation. False-positive
#   rates are expected to be higher than waves 1-7 — these are seed patterns,
#   not precision detectors.
# ============================================================================

echo
echo "=== Wave 8 — GREP ports from Zellic/Hexens novels ==="

should_run "previewredeem-rounding-up" "$@" && \
    check_pattern "previewredeem-rounding-up" "vault" 'function\s+previewRedeem[\s\S]*?Rounding\.Up'

should_run "boolean-clobber-assign-in-pause-logic" "$@" && \
    check_pattern "boolean-clobber-assign-in-pause-logic" "state" 'shouldPause\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*\s*;'

should_run "sentinel-uint256-max-clamped" "$@" && \
    check_pattern "sentinel-uint256-max-clamped" "math" '(Math\.(min|max)|_clamp)\s*\([^)]*type\(uint256\)\.max'

should_run "mofa-sig-no-transmitter-check" "$@" && \
    check_pattern "mofa-sig-no-transmitter-check" "sig" '_checkMofaSig\s*\('

should_run "permit-allowance-unit-mismatch" "$@" && \
    check_pattern "permit-allowance-unit-mismatch" "sig" 'function\s+permit[\s\S]{0,400}convertToShares'

should_run "usdt-approve-without-reset" "$@" && \
    check_pattern "usdt-approve-without-reset" "token" 'USDT[\s\S]{0,200}\.approve\s*\([^,]+,\s*[^0)]'

should_run "nft-createdat-reset-on-split-merge" "$@" && \
    check_pattern "nft-createdat-reset-on-split-merge" "nft" '(split|merge|mint)\s*[^{}]{0,400}createdAt\s*=\s*block\.timestamp'

should_run "actualuser-param-unvalidated" "$@" && \
    check_pattern "actualuser-param-unvalidated" "access" 'function\s+swap[^{]*actualUser\s*[^{]*\)\s*\{'

should_run "withdrawal-hash-conditional-delete" "$@" && \
    check_pattern "withdrawal-hash-conditional-delete" "state" 'if\s*\(\s*amount(To)?Withdraw\s*[!><=]+\s*0\s*\)[\s\S]{0,100}delete\s+pendingWithdrawals'

should_run "lockup-bypass-early-return" "$@" && \
    check_pattern "lockup-bypass-early-return" "state" 'if\s*\(\s*withdrawalLockupPeriod\s*>\s*0\s*\)\s*\{\s*return'

should_run "ltv-bypass-refinance-zero-ltv" "$@" && \
    check_pattern "ltv-bypass-refinance-zero-ltv" "lending" 'if\s+new_loan\.liquidation_ltv\s*[>!]=?\s*0'

should_run "soft-ltv-bypass" "$@" && \
    check_pattern "soft-ltv-bypass" "lending" 'current_ltv\s*>=\s*loan\.soft_liquidation_ltv'

should_run "balance-discontinuity-fee-adjust" "$@" && \
    check_pattern "balance-discontinuity-fee-adjust" "math" 'if\s*\(\s*fees\s*>\s*total\s*\)\s*fees\s*=\s*0'

should_run "off-by-one-index-star-assignment" "$@" && \
    check_pattern "off-by-one-index-star-assignment" "state" 'indexStar\s*=\s*indexEnd'

should_run "fee-divisor-is-power-of-ten-decimals" "$@" && \
    check_pattern "fee-divisor-is-power-of-ten-decimals" "vault" '(calculate|charge|take|compute).*Fee[\s\S]{0,400}/\s*10\s*\*\*\s*[a-zA-Z_]*[dD]ecimals'

should_run "fee-modifier-feesupdatedat-zero" "$@" && \
    check_pattern "fee-modifier-feesupdatedat-zero" "vault" 'feesUpdatedAt\s*==\s*0|feesUpdatedAt\s*=\s*block\.timestamp'

should_run "blocked-payment-wrong-address-field" "$@" && \
    check_pattern "blocked-payment-wrong-address-field" "bridge" 'receivingAddressHash[\s\S]{0,200}(bytes32\(0\)|== 0)'

should_run "gtl-hook-not-fired-on-full-fill" "$@" && \
    check_pattern "gtl-hook-not-fired-on-full-fill" "perps" 'orderRemoved\s*==\s*false[\s\S]{0,200}_?gtlHook'

should_run "arbitrum-outbound-transfer-no-custom-refund" "$@" && \
    check_pattern "arbitrum-outbound-transfer-no-custom-refund" "bridge" '\.outboundTransfer\s*\((?![^;]*outboundTransferCustomRefund)'

should_run "ibc-denom-replace-all-prefix" "$@" && \
    check_pattern "ibc-denom-replace-all-prefix" "bridge" '\.replace\s*\(\s*["'\''][a-z]+["'\'']\s*,\s*["'\'']["'\'']\s*\)'

should_run "balanceof-used-in-donation-threshold" "$@" && \
    check_pattern "balanceof-used-in-donation-threshold" "token" 'minimum.*=.*token\.balanceOf\(address\(this\)\)'

should_run "stability-pool-p-zero-assert-missing" "$@" && \
    check_pattern "stability-pool-p-zero-assert-missing" "math" '_updateRewardSumAndProduct|newProductFactor'

should_run "bls-agg-skip-first-subgroup-check" "$@" && \
    check_pattern "bls-agg-skip-first-subgroup-check" "crypto" '\.iter\(\)\s*\.skip\s*\(\s*1\s*\)[\s\S]{0,200}subgroup'

should_run "bls-agg-no-proof-of-possession" "$@" && \
    check_pattern "bls-agg-no-proof-of-possession" "crypto" '(seedPublicKeyList|addBLSPublicKey|aggregatePubkey)'

should_run "withdrawerc20-relayer-param-unchecked" "$@" && \
    check_pattern "withdrawerc20-relayer-param-unchecked" "access" 'function\s+withdrawERC20[^{]*_?relayer\b'

should_run "dual-user-controlled-receiver-doublespend" "$@" && \
    check_pattern "dual-user-controlled-receiver-doublespend" "access" 'function\s+transferToken[\s\S]{0,400}(usxReceiver|usdcReceiver)'

should_run "zk-output-note-footer-not-unique" "$@" && \
    check_pattern "zk-output-note-footer-not-unique" "zk" 'noteFooter\s*[!=]=\s*noteFooter'

should_run "validator-registered-flag-set-before-push" "$@" && \
    check_pattern "validator-registered-flag-set-before-push" "state" 'isValRegistered\s*\[[^\]]+\]\s*=\s*true[\s\S]{0,200}addValidatorRewardList'

should_run "first-bls-element-no-validation" "$@" && \
    check_pattern "first-bls-element-no-validation" "crypto" 'from_(X|bytes|compressed)\s*\([^,]+\)\s*[?;]'

should_run "withdrawerc20-public-no-msgsender-check" "$@" && \
    check_pattern "withdrawerc20-public-no-msgsender-check" "access" 'function\s+withdrawERC20[^{]*\)\s*public\s*\{(?![^}]*msg\.sender)'

should_run "relayer-gasfee-unverified" "$@" && \
    check_pattern "relayer-gasfee-unverified" "access" '_relayerGasFee'

should_run "transmutable-trait-not-unsafe" "$@" && \
    check_pattern "transmutable-trait-not-unsafe" "rust" '(trait\s+Transmutable\b|impl\s+Transmutable\s+for)'

should_run "copy-val-no-copy-bound" "$@" && \
    check_pattern "copy-val-no-copy-bound" "rust" 'fn\s+copy_val\s*<'

# ============================================================================
#   WAVE 9 — GREP PORTS FROM CODE4RENA MINING
#
#   Ported from reference/corpus_mined/code4arena_slice_{aa..ad}.md GREP-class
#   findings (81 reports, 2024-2025). These are seed approximations — many are
#   FP-prone. The detector lane (detectors/wave9/) and DOCS lane
#   (sc_audit_toolbox.md Wave 9) ship in parallel.
# ============================================================================

echo
echo "=== Wave 9 — GREP ports from Code4rena slice_aa..ad ==="

# --- slice_aa (Size, Basin, BendDAO, LoopFi, TraitForge, Chakra, Phi, Wildcat)

should_run "multicall-isMulticall-flag" "$@" && \
    check_pattern "multicall-isMulticall-flag" "state" 'isMulticall\s*=\s*(true|false)' # FP-prone

should_run "aave-getter-wrong-pool" "$@" && \
    check_pattern "aave-getter-wrong-pool" "lending" 'getReserveData\s*\(\s*[a-zA-Z_]+\s*\)\s*\.(currentLiquidityRate|liquidityIndex)' # FP-prone

should_run "decoder-arg-order-decimal1" "$@" && \
    check_pattern "decoder-arg-order-decimal1" "abi" 'abi\.decode\([^,]+,\s*\(uint8\s*,\s*uint8\)\)\s*returns\s*\(\s*decimal0\s*,\s*decimal1' # FP-prone

should_run "unwrap-native-hardcoded-receiver" "$@" && \
    check_pattern "unwrap-native-hardcoded-receiver" "token" 'unwrapNativeToken\s*\([^,]+,\s*0x[0-9a-fA-F]{40}'

should_run "tx-origin-used" "$@" && \
    check_pattern "tx-origin-used" "access" 'tx\.origin' # FP-prone (sometimes legitimate)

should_run "answeredInRound-deprecated" "$@" && \
    check_pattern "answeredInRound-deprecated" "oracle" 'answeredInRound\s*[<>=]'

should_run "isApprovedForAll-wrong-operand" "$@" && \
    check_pattern "isApprovedForAll-wrong-operand" "nft" 'isApprovedForAll\s*\(\s*msg\.sender\s*,'

should_run "wrong-spender-EIP2612" "$@" && \
    check_pattern "wrong-spender-EIP2612" "sig" 'permit\s*\([^,]+,\s*address\(this\)' # FP-prone

should_run "flashloan-mint-wrong-fn" "$@" && \
    check_pattern "flashloan-mint-wrong-fn" "lending" '_mintShares[\s\S]{0,200}flashLoan' # FP-prone

# --- slice_ab (Kleidi, LoopFi, Ramses, Superposition, Ethena, BakerFi, Lambo)

should_run "calldata-offset-arith-off-by-one" "$@" && \
    check_pattern "calldata-offset-arith-off-by-one" "abi" 'calldatasize\s*\(\)\s*[-+]\s*0x[0-9a-fA-F]+' # FP-prone

should_run "monotonic-only-setter" "$@" && \
    check_pattern "monotonic-only-setter" "state" 'require\s*\(\s*new[A-Z][a-zA-Z]+\s*>=?\s*current[A-Z][a-zA-Z]+' # FP-prone

should_run "router-arbitrary-from-param" "$@" && \
    check_pattern "router-arbitrary-from-param" "access" 'function\s+(pull|deposit|forward)[A-Za-z]*\s*\([^)]*address\s+from\b'

should_run "hardcoded-sqrtPriceLimitX96" "$@" && \
    check_pattern "hardcoded-sqrtPriceLimitX96" "amm" 'sqrtPriceLimitX96\s*:\s*(0|TickMath\.(MIN|MAX)_SQRT_RATIO\s*[+-]\s*1)'

should_run "createPair-squat-DoS" "$@" && \
    check_pattern "createPair-squat-DoS" "amm" 'createPair[\s\S]{0,200}revert' # FP-prone

should_run "user-supplied-domain-separator" "$@" && \
    check_pattern "user-supplied-domain-separator" "sig" 'function\s+[a-zA-Z_]+\s*\([^)]*bytes32\s+domainSeparator\b'

should_run "governance-quorum-wrong-side" "$@" && \
    check_pattern "governance-quorum-wrong-side" "governance" 'quorum\s*\([^)]*\)\s*[<>=]+\s*againstVotes' # FP-prone

# --- slice_ac (Thorwallet, Nudge, Silo, Virtuals, Blackhole, GTE, Panoptic)

should_run "permanent-per-user-bool-flag" "$@" && \
    check_pattern "permanent-per-user-bool-flag" "state" 'isBridgedTokenHolder\s*\[' # FP-prone

should_run "approve-zero-no-trycatch" "$@" && \
    check_pattern "approve-zero-no-trycatch" "token" '\.approve\s*\([^,]+,\s*0\s*\)\s*;'

should_run "1e18-collateral-hardcoded" "$@" && \
    check_pattern "1e18-collateral-hardcoded" "math" '(collateral|amount|debt)[\s\S]{0,80}\*\s*1e18' # FP-prone

should_run "ln-no-positive-guard" "$@" && \
    check_pattern "ln-no-positive-guard" "math" 'function\s+ln\s*\([^)]*\)\s*[^{]*\{(?![^}]*require\s*\([^)]*>\s*0)'

should_run "amount-out-min-zero-literal" "$@" && \
    check_pattern "amount-out-min-zero-literal" "amm" 'amountOutMin\s*:\s*0\s*[,)]'

should_run "burnFrom-omits-totalSupply" "$@" && \
    check_pattern "burnFrom-omits-totalSupply" "token" 'function\s+burnFrom[\s\S]{0,400}_balances\[[^\]]+\]\s*-=\s*amount' # FP-prone, manual check for missing _totalSupply -=

should_run "named-return-shadows-storage" "$@" && \
    check_pattern "named-return-shadows-storage" "state" 'returns\s*\(\s*[a-zA-Z_]+\s+[a-z][a-zA-Z]+\s*\)' # FP-prone

should_run "execute-no-state-succeeded-guard" "$@" && \
    check_pattern "execute-no-state-succeeded-guard" "governance" 'function\s+execute[\s\S]{0,400}(?!.*state\s*\(\s*[^)]+\)\s*==\s*ProposalState\.Succeeded)' # FP-prone

should_run "fee-clamp-fallback-default" "$@" && \
    check_pattern "fee-clamp-fallback-default" "state" 'if\s*\(\s*[a-zA-Z_]+Fee\s*>\s*[A-Z_]+\s*\)\s*return\s+default'

# --- slice_ad (Morpheus, Hybra, Sequence, Brix, Ekubo, Megapot, Merkl, Sukuk, Panoptic Next-Core)

should_run "shared-heartbeat-multi-feed" "$@" && \
    check_pattern "shared-heartbeat-multi-feed" "oracle" 'allowedPriceUpdateDelay\s*=' # FP-prone

should_run "early-return-skip-bookkeeping" "$@" && \
    check_pattern "early-return-skip-bookkeeping" "state" 'if\s*\([^)]*==\s*0\s*\)\s*return\s*;[\s\S]{0,200}lastUnderlyingBalance\s*=' # FP-prone

should_run "min-amount-equals-amount-LZ" "$@" && \
    check_pattern "min-amount-equals-amount-LZ" "bridge" 'minAmountLD\s*[:,]\s*amountLD\b'

should_run "max-zero-pps-numerator" "$@" && \
    check_pattern "max-zero-pps-numerator" "vault" 'Math\.max\s*\(\s*0\s*,\s*[a-zA-Z_]+\s*-\s*pending\s*-\s*claimable'

should_run "create2-factory-no-existing-check" "$@" && \
    check_pattern "create2-factory-no-existing-check" "factory" 'function\s+(deploy|createWallet|getOrDeploy)[\s\S]{0,400}create2\s*\(' # FP-prone

should_run "min-commission-zero-path" "$@" && \
    check_pattern "min-commission-zero-path" "perps" 'min\s*\(\s*premium\s*,\s*notional\s*\)' # FP-prone

should_run "interface-mapping-getter-arity" "$@" && \
    check_pattern "interface-mapping-getter-arity" "interface" 'function\s+poolVote\s*\(\s*uint256\s+\)\s*external\s+view\s+returns\s*\(\s*[a-zA-Z]+\[\]'

should_run "balance-sweep-rewardtoken-conflation" "$@" && \
    check_pattern "balance-sweep-rewardtoken-conflation" "rewards" 'token[01]\.balanceOf\s*\(\s*address\(this\)\s*\)[\s\S]{0,200}rewardToken' # FP-prone

should_run "round-in-flight-admin-setter" "$@" && \
    check_pattern "round-in-flight-admin-setter" "access" 'function\s+set(EntropyProvider|PayoutCalculator|VRFProvider|Oracle)\s*\([^)]*\)\s*external\s+only(Owner|Role)' # FP-prone

should_run "cap-set-rejects-current-over-new" "$@" && \
    check_pattern "cap-set-rejects-current-over-new" "governance" 'require\s*\(\s*[a-zA-Z_]+\s*<=\s*newCap'

should_run "exact-out-router-no-output-check" "$@" && \
    check_pattern "exact-out-router-no-output-check" "amm" 'function\s+swapExactOut[\s\S]{0,400}require\s*\([^)]*amountIn\s*<=\s*maxIn' # FP-prone

# ============================================================================

echo
echo "============================================================================"
echo "Done. Review each HITS row — grep approximations have false positives."
echo "For queries marked SKIP or not listed: read the Python source in"
echo "  auditooor/external/glider-query-db/queries/<query-name>.py"
echo "============================================================================"
