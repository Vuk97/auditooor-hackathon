#!/usr/bin/env bash
# gen-composition-fuzz.sh — R57 Track C composition invariant harness generator
#
# Usage:
#   gen-composition-fuzz.sh <workspace-dir> <contract-list-file>
#
# contract-list-file: newline-delimited, each line: <Name>:<relative/path/to/Contract.sol>
#
# Output: <workspace-dir>/composition_fuzz/<Name1>_vs_<Name2>[_vs_Name3].t.sol
#
# Design goals (first-draft, ~70% operator-ready):
#   - Extracts public/external function signatures via grep
#   - Generates Foundry invariant harness with StatefulHandler
#   - Emits N named invariant stubs the operator fills in
#   - Skips abstract contracts with a warning
#   - Uses best-effort constructor arg defaults

set -euo pipefail

# ── argument check ───────────────────────────────────────────────────────────
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <workspace-dir> <contract-list-file>" >&2
    exit 1
fi

WORKSPACE="$1"
CONTRACT_LIST="$2"

if [[ ! -d "$WORKSPACE" ]]; then
    echo "[error] workspace dir does not exist: $WORKSPACE" >&2
    exit 1
fi
if [[ ! -f "$CONTRACT_LIST" ]]; then
    echo "[error] contract list file not found: $CONTRACT_LIST" >&2
    exit 1
fi

OUT_DIR="$WORKSPACE/composition_fuzz"
mkdir -p "$OUT_DIR"

# ── helpers ───────────────────────────────────────────────────────────────────

resolve_sol_path() {
    local raw_path="$1"
    if [[ "$raw_path" = /* ]]; then
        printf '%s\n' "$raw_path"
        return 0
    fi
    if [[ -f "$WORKSPACE/$raw_path" ]]; then
        printf '%s\n' "$WORKSPACE/$raw_path"
        return 0
    fi
    printf '%s\n' "$raw_path"
}

# Detect if a .sol file declares the contract abstract
is_abstract() {
    local sol_path="$1"
    local name="$2"
    local resolved
    resolved="$(resolve_sol_path "$sol_path")"
    # look for: abstract contract <Name>
    grep -qE "^abstract contract ${name}\b" "$resolved" 2>/dev/null
}

# Extract public/external function signatures from a sol file
# Returns lines like:  functionName(type1 name1, type2 name2) [returns (T)]
# We only capture the name+param types, good enough for handler wrappers
extract_sigs() {
    local sol_path="$1"
    local resolved
    resolved="$(resolve_sol_path "$sol_path")"
    # Match: function <name>(...) [public|external] [...]
    # We normalise to a single line form; multiline declarations not handled (rare in these contracts)
    grep -oE 'function [a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*(public|external)' "$resolved" 2>/dev/null \
        | sed 's/function //g' \
        | sed 's/  */ /g'
}

# Extract just function names (no params) from a sig list
sig_to_name() {
    sed 's/(.*//'
}

# Derive a short human-readable constructor arg list from a sol file
# Returns "arg0 arg1 ..." in typical order found in constructor(...)
extract_ctor_params() {
    local sol_path="$1"
    local resolved
    resolved="$(resolve_sol_path "$sol_path")"
    # Grab the constructor's param block (first constructor(...))
    grep -oE 'constructor\s*\([^)]*\)' "$resolved" 2>/dev/null | head -1 \
        | grep -oE '\([^)]*\)' | tr -d '()' | sed 's/,/ /g'
}

# ── read contract list ────────────────────────────────────────────────────────
declare -a NAMES=()
declare -a PATHS=()

while IFS=':' read -r cname cpath || [[ -n "$cname" ]]; do
    # skip blank lines and comments
    [[ -z "$cname" || "$cname" == \#* ]] && continue
    cpath="${cpath%$'\r'}"  # strip CR on Windows-generated files
    NAMES+=("$cname")
    PATHS+=("$cpath")
done < "$CONTRACT_LIST"

if [[ ${#NAMES[@]} -lt 2 ]]; then
    echo "[error] contract-list-file must have at least 2 entries" >&2
    exit 1
fi

# ── abstract detection + skip ─────────────────────────────────────────────────
declare -a ACTIVE_NAMES=()
declare -a ACTIVE_PATHS=()

for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    path="${PATHS[$i]}"
    if is_abstract "$path" "$name"; then
        echo "[info] skipping abstract $name ($path)"
    else
        ACTIVE_NAMES+=("$name")
        ACTIVE_PATHS+=("$path")
    fi
done

if [[ ${#ACTIVE_NAMES[@]} -lt 2 ]]; then
    echo "[error] fewer than 2 non-abstract contracts remain — nothing to compose" >&2
    exit 1
fi

# ── build output filename ─────────────────────────────────────────────────────
OUT_NAME="${ACTIVE_NAMES[0]}"
for i in "${!ACTIVE_NAMES[@]}"; do
    [[ $i -eq 0 ]] && continue
    OUT_NAME="${OUT_NAME}_vs_${ACTIVE_NAMES[$i]}"
done
OUT_FILE="$OUT_DIR/${OUT_NAME}.t.sol"
echo "[info] generating $OUT_FILE"

# ── collect sigs per contract ─────────────────────────────────────────────────
declare -a ALL_SIGS=()   # parallel arrays
declare -a SIG_OWNER=()  # which contract the sig belongs to
declare -a SIG_NAMES=()  # just the function name

for i in "${!ACTIVE_NAMES[@]}"; do
    name="${ACTIVE_NAMES[$i]}"
    path="${ACTIVE_PATHS[$i]}"
    resolved_path="$(resolve_sol_path "$path")"
    if [[ ! -f "$resolved_path" ]]; then
        echo "[warn] file not found for $name: $path — skipping sigs"
        continue
    fi
    while IFS= read -r sig; do
        [[ -z "$sig" ]] && continue
        fname=$(echo "$sig" | sed 's/(.*//')
        # skip constructor / receive / fallback  / internal-looking names
        [[ "$fname" == "constructor" || "$fname" == "receive" || "$fname" == "fallback" ]] && continue
        ALL_SIGS+=("$sig")
        SIG_OWNER+=("$name")
        SIG_NAMES+=("$fname")
    done < <(extract_sigs "$path")
done

TOTAL_SIGS=${#ALL_SIGS[@]}
echo "[info] extracted $TOTAL_SIGS public/external signatures across ${#ACTIVE_NAMES[@]} contracts"

# ── detect a common ERC20 collateral token guess ─────────────────────────────
# If any path mentions USDC / collateral, we'll reference a mock
USES_ERC20="false"
for p in "${ACTIVE_PATHS[@]}"; do
    resolved_path="$(resolve_sol_path "$p")"
    grep -qiE 'IERC20|ERC20|collateral|usdc' "$resolved_path" 2>/dev/null && USES_ERC20="true" && break
done

USES_ERC1155="false"
for p in "${ACTIVE_PATHS[@]}"; do
    resolved_path="$(resolve_sol_path "$p")"
    grep -qiE 'ERC1155|ConditionalTokens|safeBatchTransfer' "$resolved_path" 2>/dev/null && USES_ERC1155="true" && break
done

# ── detect SPDX + pragma from first contract ─────────────────────────────────
FIRST_PATH="${ACTIVE_PATHS[0]}"
FIRST_RESOLVED_PATH="$(resolve_sol_path "$FIRST_PATH")"
SRC_SPDX=$(grep -m1 'SPDX-License-Identifier' "$FIRST_RESOLVED_PATH" 2>/dev/null | grep -oE 'SPDX-License-Identifier: [^ ]+' || echo "SPDX-License-Identifier: MIT")
SRC_PRAGMA=$(grep -m1 '^pragma solidity' "$FIRST_RESOLVED_PATH" 2>/dev/null || echo "pragma solidity 0.8.34;")
# For test files, always use MIT + 0.8.34
GEN_SPDX="// SPDX-License-Identifier: MIT"
GEN_PRAGMA="pragma solidity 0.8.34;"

# ── build import paths (relative from OUT_FILE perspective) ──────────────────
# OUT_FILE is in $WORKSPACE/composition_fuzz/
# contract paths are given as-is; operator should adjust remappings if needed

# ── emit the Solidity file ────────────────────────────────────────────────────
cat > "$OUT_FILE" <<SOLIDITY_EOF
${GEN_SPDX}
${GEN_PRAGMA}

// =============================================================================
// AUTO-GENERATED by gen-composition-fuzz.sh (R57 Track C)
// Contracts: $(echo "${ACTIVE_NAMES[@]}" | tr ' ' ', ')
// Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
//
// PURPOSE: Foundry invariant harness exercising 2+ contracts together and
// asserting cross-contract state consistency.
//
// OPERATOR TODO LIST:
//   1. Fix import paths below to match your foundry.toml remappings.
//   2. Fill in real constructor args wherever TODO: appears.
//   3. Implement the stub invariants — each has a comment explaining what to check.
//   4. Add StatefulHandler actions that are protocol-specific (e.g. fee paths,
//      redemption, migration, role escalation).
//   5. Run: forge test --match-contract CompositionFuzz_${OUT_NAME}
// =============================================================================

import { Test, StdInvariant } from "forge-std/Test.sol";
import { ERC20 } from "@solady/src/tokens/ERC20.sol";
import { ERC1155 } from "@solady/src/tokens/ERC1155.sol";

SOLIDITY_EOF

# imports for each contract
for i in "${!ACTIVE_NAMES[@]}"; do
    name="${ACTIVE_NAMES[$i]}"
    path="${ACTIVE_PATHS[$i]}"
    echo "// TODO: adjust import path to match your remappings / project layout" >> "$OUT_FILE"
    echo "import { ${name} } from \"${path}\";" >> "$OUT_FILE"
done

cat >> "$OUT_FILE" <<'SOLIDITY_EOF2'

// ─────────────────────────────────────────────────────────────────────────────
//                           STATEFUL HANDLER
// ─────────────────────────────────────────────────────────────────────────────

/// @title StatefulHandler
/// @notice Drives the Foundry invariant fuzzer by wrapping each contract's
///         public/external functions as bounded actor calls.
/// @dev    Ghost variables track aggregate state for cross-contract invariants.
contract StatefulHandler is Test {

    // ── contract instances ────────────────────────────────────────────────────
SOLIDITY_EOF2

for name in "${ACTIVE_NAMES[@]}"; do
    # lowercase for variable name
    varname=$(echo "$name" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
    echo "    ${name} public ${varname};" >> "$OUT_FILE"
done

cat >> "$OUT_FILE" <<'SOLIDITY_EOF3'

    // ── actors ────────────────────────────────────────────────────────────────
    address public actor0 = address(0x1001);
    address public actor1 = address(0x1002);
    address public actor2 = address(0x1003);
    uint256 internal constant MAX_BOUND = 1_000_000e6; // 6-decimal cap

    // ── ghost variables ───────────────────────────────────────────────────────
    uint256 public ghost_totalDeposited;   // sum of collateral deposited across contracts
    uint256 public ghost_totalWithdrawn;   // sum of collateral withdrawn across contracts
    uint256 public ghost_callCount;        // total handler calls
    uint256 public ghost_successCount;     // successful (non-reverting) calls
    mapping(address => uint256) public ghost_userDeposit;   // per-actor deposit ledger
    mapping(address => uint256) public ghost_userWithdraw;  // per-actor withdraw ledger

SOLIDITY_EOF3

# constructor
echo "    constructor(" >> "$OUT_FILE"
for i in "${!ACTIVE_NAMES[@]}"; do
    name="${ACTIVE_NAMES[$i]}"
    varname=$(echo "$name" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
    sep=","
    [[ $i -eq $((${#ACTIVE_NAMES[@]}-1)) ]] && sep=""
    echo "        ${name} _${varname}${sep}" >> "$OUT_FILE"
done
echo "    ) {" >> "$OUT_FILE"
for name in "${ACTIVE_NAMES[@]}"; do
    varname=$(echo "$name" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
    echo "        ${varname} = _${varname};" >> "$OUT_FILE"
done
echo "    }" >> "$OUT_FILE"
echo "" >> "$OUT_FILE"

# ── emit one handler action per unique function name (first 20 to stay sane) ──
echo "    // ── bounded action wrappers ─────────────────────────────────────────────" >> "$OUT_FILE"
echo "    // Each wraps a real contract function; operator should add realistic logic." >> "$OUT_FILE"
echo "" >> "$OUT_FILE"

seen_fns=()
emitted=0
MAX_ACTIONS=20

for i in "${!ALL_SIGS[@]}"; do
    [[ $emitted -ge $MAX_ACTIONS ]] && break
    sig="${ALL_SIGS[$i]}"
    owner="${SIG_OWNER[$i]}"
    fname="${SIG_NAMES[$i]}"

    # Skip duplicate names across contracts (keep first)
    already=false
    for s in "${seen_fns[@]:-}"; do
        [[ "$s" == "${owner}_${fname}" ]] && already=true && break
    done
    $already && continue
    seen_fns+=("${owner}_${fname}")

    varname=$(echo "$owner" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
    # Build a compilable no-op stub. The try call is left as a comment so the
    # file compiles out of the box; operator uncomments + supplies real args.
    cat >> "$OUT_FILE" <<HANDLER_EOF
    /// @notice Handler action: calls ${owner}.${fname}(...)
    /// @dev    Stub — operator must uncomment the try block and supply real args.
    ///         Use _bound(seed, min, max) to derive bounded arguments.
    function act_${owner}_${fname}(uint256 seed) external {
        ghost_callCount++;
        // TODO: uncomment and fill in args below.
        // Pick an actor with: address actor = seed % 3 == 0 ? actor0 : seed % 3 == 1 ? actor1 : actor2;
        // Bound amounts with:  uint256 amount = _bound(seed, 0, MAX_BOUND);
        // vm.prank(actor);
        // try ${varname}.${fname}(/* TODO: args */) {
        //     ghost_successCount++;
        // } catch { }
        // STUB no-op (compiles): remove this line once try block is active
        if (seed == type(uint256).max) ghost_successCount++; // unreachable sentinel
    }

HANDLER_EOF
    ((emitted++)) || true
done

cat >> "$OUT_FILE" <<'SOLIDITY_EOF4'
} // end StatefulHandler

// ─────────────────────────────────────────────────────────────────────────────
//                          COMPOSITION FUZZ TEST
// ─────────────────────────────────────────────────────────────────────────────

SOLIDITY_EOF4

echo "/// @title CompositionFuzz_${OUT_NAME}" >> "$OUT_FILE"
echo "/// @notice Cross-contract composition invariant harness (R57 Track C)" >> "$OUT_FILE"
echo "/// @dev    Operator should implement all TODO stubs before running." >> "$OUT_FILE"
echo "contract CompositionFuzz_${OUT_NAME} is StdInvariant, Test {" >> "$OUT_FILE"

echo "" >> "$OUT_FILE"
echo "    // ── instances ────────────────────────────────────────────────────────────" >> "$OUT_FILE"
for name in "${ACTIVE_NAMES[@]}"; do
    varname=$(echo "$name" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
    echo "    ${name} public ${varname};" >> "$OUT_FILE"
done

echo "    StatefulHandler public handler;" >> "$OUT_FILE"
echo "" >> "$OUT_FILE"

# ── setUp ──────────────────────────────────────────────────────────────────────
cat >> "$OUT_FILE" <<'SETUP_EOF'
    function setUp() public virtual {
        // ── deploy contracts ─────────────────────────────────────────────────
        //
        // TODO: replace address(this) / address(0) / 1e18 with real values.
        // Constructor arg heuristics below are best-effort; the generator
        // cannot infer your specific deployment topology.
        //
SETUP_EOF

for i in "${!ACTIVE_NAMES[@]}"; do
    name="${ACTIVE_NAMES[$i]}"
    varname=$(echo "$name" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
    path="${ACTIVE_PATHS[$i]}"
    ctor_params=$(extract_ctor_params "$path" 2>/dev/null || echo "")
    # Build a comment listing the known param names
    echo "        // ${name} constructor params: ${ctor_params:-<none detected>}" >> "$OUT_FILE"
    echo "        // TODO: provide real constructor args" >> "$OUT_FILE"
    echo "        // ${varname} = new ${name}(/* TODO: constructor args */);" >> "$OUT_FILE"
    echo "" >> "$OUT_FILE"
done

cat >> "$OUT_FILE" <<'SETUP_EOF2'
        // ── deploy handler ───────────────────────────────────────────────────
        handler = new StatefulHandler(
SETUP_EOF2

for i in "${!ACTIVE_NAMES[@]}"; do
    name="${ACTIVE_NAMES[$i]}"
    varname=$(echo "$name" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
    sep=","
    [[ $i -eq $((${#ACTIVE_NAMES[@]}-1)) ]] && sep=""
    echo "            ${varname}${sep}" >> "$OUT_FILE"
done

cat >> "$OUT_FILE" <<'SETUP_EOF3'
        );

        // ── configure invariant fuzzer ───────────────────────────────────────
        // TODO: populate selectors[] with the specific act_* functions you want
        //       the fuzzer to call.  Add / remove as needed.
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("act_example(uint256)")); // TODO: replace

        targetContract(address(handler));
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
    }

SETUP_EOF3

# ── invariant stubs ────────────────────────────────────────────────────────────

# Always emit the global solvency default
cat >> "$OUT_FILE" <<'INV_EOF'
    // =========================================================================
    //                          INVARIANT STUBS
    // =========================================================================
    // Each invariant below is a named placeholder.  The comment explains what
    // the operator should implement.  Start with the ones most relevant to your
    // composition pair; delete the rest.
    // =========================================================================

    // ── default: global solvency ──────────────────────────────────────────────
    /// @notice The sum of tokens deposited across all contracts equals the sum
    ///         of tokens withdrawable (no value leaks or appears from nowhere).
    /// @dev    Operator: replace with real balance tracking.
    ///         E.g.  sum(contractA.totalAssets()) + sum(contractB.shares()) == totalDeposited
    ///         Use ghost_totalDeposited / ghost_totalWithdrawn from handler.
    function invariant_globalSolvency() public view {
        // TODO: implement with real asset accounting
        // assertEq(ghost_totalDeposited - ghost_totalWithdrawn,
        //          contractA.totalAssets() + contractB.totalAssets());
        assertGe(handler.ghost_totalDeposited(), handler.ghost_totalWithdrawn());
    }

INV_EOF

# ── protocol-specific stubs — one per contract pair ──────────────────────────
# We emit cross-product stubs for every pair of (contractA, contractB)
pair_count=0
for i in "${!ACTIVE_NAMES[@]}"; do
    for j in "${!ACTIVE_NAMES[@]}"; do
        [[ $j -le $i ]] && continue
        A="${ACTIVE_NAMES[$i]}"
        B="${ACTIVE_NAMES[$j]}"
        varA=$(echo "$A" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')
        varB=$(echo "$B" | awk '{print tolower(substr($0,1,1)) substr($0,2)}')

        cat >> "$OUT_FILE" <<PAIR_EOF
    // ── pair: ${A} × ${B} ──────────────────────────────────────────────────────

    /// @notice Cross-contract token balance: total assets held by ${A}
    ///         must never exceed total supply minted via ${B} (or vice versa).
    /// @dev    Operator: fill in the real balance/totalSupply getters.
    ///         Pattern: contractA.totalAssets() <= contractB.totalSupply()
    function invariant_${A}_${B}_assetSupplyBound() public view {
        // TODO: replace with real getters
        // assertLe(${varA}.totalAssets(), ${varB}.totalSupply());
        assertTrue(true); // stub — operator must implement
    }

    /// @notice Paused state propagates consistently: if ${A} is paused,
    ///         any operation routed through ${B} that touches ${A} must also fail.
    /// @dev    Operator: check that the paused flag in both contracts is
    ///         either both true or both false (if they share a pause admin).
    function invariant_${A}_${B}_pausedStateConsistency() public view {
        // TODO: if both contracts expose a paused() view, assert they agree.
        // bool aPaused = ${varA}.paused();
        // bool bPaused = ${varB}.paused(address(someAsset));
        // assertEq(aPaused, bPaused);  // or: if (aPaused) assertTrue(bPaused)
        assertTrue(true); // stub — operator must implement
    }

    /// @notice Shares are proportional: the ratio of per-user shares in ${A}
    ///         matches the ratio in ${B} (relevant for vault/adapter pairs).
    /// @dev    Operator: fill in user share getters and assert ratio consistency
    ///         across the actor set.
    function invariant_${A}_${B}_sharesProportional() public view {
        // TODO: for each actor, check share proportions are consistent
        // e.g. ${varA}.sharesOf(actor0) * ${varB}.totalShares() ==
        //      ${varB}.sharesOf(actor0) * ${varA}.totalShares()
        assertTrue(true); // stub — operator must implement
    }

    /// @notice No value extracted across ${A}→${B}→${A} round trip:
    ///         depositing into ${A} then routing through ${B} should not
    ///         yield more collateral than originally deposited.
    /// @dev    Operator: track pre/post balances of a sentinel actor and
    ///         assert ghost_userWithdraw[actor] <= ghost_userDeposit[actor].
    function invariant_${A}_${B}_noValueExtraction() public view {
        // TODO: compare per-actor deposit vs withdraw from handler ghost vars
        // assertLe(handler.ghost_userWithdraw(actor0), handler.ghost_userDeposit(actor0));
        assertTrue(true); // stub — operator must implement
    }

PAIR_EOF
        ((pair_count++)) || true
    done
done

# Count total invariants: 1 (global solvency) + pair_count * 4
TOTAL_INVS=$((1 + pair_count * 4))

cat >> "$OUT_FILE" <<'TAIL_EOF'
} // end CompositionFuzz contract
TAIL_EOF

echo "[info] done: $OUT_FILE"
echo "[info] invariant stubs emitted: $TOTAL_INVS"
echo "[info] handler actions emitted: $emitted"
echo "[info] operator-TODO items: $(grep -c 'TODO' "$OUT_FILE" 2>/dev/null || echo '?')"
