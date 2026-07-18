// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/**
 * @title ForkEtchCrossFunctionBase
 * @notice GENERIC, reusable base for FORK-MODE + ``vm.etch`` mutation-verified
 *         CROSS-FUNCTION harnesses over a live Diamond / L2 contract.
 *
 * EXTRACTED FROM THE PROVEN bean recipe
 * -------------------------------------
 * The one-off ``XfnForkFeasibility.t.sol`` proved (all 5 tests pass on the live
 * Arbitrum Beanstalk Diamond) that a cross-function economic invariant can be
 * mutation-verified by:
 *   1. forking the live chain and selecting it,
 *   2. loupe-resolving the facet that serves the cross-function selectors,
 *   3. etching the OFFLINE-LINKED clean recompile at the facet (faithful baseline),
 *   4. etching the OFFLINE-LINKED mutant recompile at the same facet,
 *   5. asserting the economic invariant FLIPS (clean PASS -> mutant FAIL).
 *
 * This base contract generifies steps 1-5. A concrete harness only fills in:
 *   - the chain config (RPC env var, DIAMOND, facet selectors) via the
 *     constructor-set immutables (or by overriding ``_forkConfig``),
 *   - the per-pair ECONOMIC INVARIANT body (``_roundTripHolds``) - the human
 *     Step-4b judgement of what conservation the function pair must preserve,
 *   - the lib etch list + facet hex paths (emitted by the python producer).
 *
 * The differential machinery (``_assertMutantKilled``) is NOT a fill-in: it is
 * the reusable kill oracle. A vacuous invariant (e.g. ``assertTrue(true)``) will
 * NOT flip and the differential test fails - the harness cannot false-green.
 */
abstract contract ForkEtchCrossFunctionBase is Test {
    // ---- chain / target config (concrete harness sets these) ----
    // The RPC env var name to fork from (e.g. "ARB_RPC").
    string internal RPC_ENV;
    // The live Diamond proxy the cross-function pair routes through.
    address internal DIAMOND;
    // The facet impl address (loupe-resolved) the cross-function selectors land
    // on; the address we etch clean/mutant bytecode at.
    address internal FACET;

    // ---- offline-linked library etch list (producer emits these) ----
    // Parallel arrays: LIB_ADDRS[i] is etched with the bytecode at LIB_HEX[i].
    // These are the fixed fork addresses the facet's deployedBytecode was
    // offline-linked to (see tools/lib/fork_etch_link.py / assign_lib_addresses).
    address[] internal LIB_ADDRS;
    string[] internal LIB_HEX; // file paths to 0x-prefixed deployedBytecode hex

    // ---- facet bytecode hex paths (producer emits these) ----
    string internal CLEAN_HEX; // offline-linked CLEAN facet deployedBytecode
    string internal MUTANT_HEX; // offline-linked MUTANT facet deployedBytecode

    // ------------------------------------------------------------------
    // Fork + loupe resolution
    // ------------------------------------------------------------------
    function _fork() internal {
        string memory rpc = vm.envString(RPC_ENV);
        vm.createSelectFork(rpc);
    }

    /// @dev Diamond-loupe facetAddress(selector). Concrete harness asserts the
    ///      cross-function selectors all resolve to FACET in its liveness test.
    function _facetAddress(bytes4 selector) internal view returns (address) {
        (bool ok, bytes memory ret) = DIAMOND.staticcall(
            abi.encodeWithSignature("facetAddress(bytes4)", selector)
        );
        require(ok && ret.length >= 32, "loupe facetAddress failed");
        return abi.decode(ret, (address));
    }

    /// @dev Assert every selector in the cross-function pair routes to FACET, so
    ///      etching FACET actually swaps the code the pair executes.
    function _assertSelectorsRouteToFacet(bytes4[] memory selectors) internal view {
        for (uint256 i = 0; i < selectors.length; i++) {
            require(
                _facetAddress(selectors[i]) == FACET,
                "selector does not route to FACET (etch would be a no-op)"
            );
        }
        require(FACET.code.length > 0, "FACET has no bytecode on fork");
    }

    // ------------------------------------------------------------------
    // Etch: libraries first (so the facet's delegatecalls resolve), then facet
    // ------------------------------------------------------------------
    function _etchLibs() internal {
        require(LIB_ADDRS.length == LIB_HEX.length, "lib addr/hex length mismatch");
        for (uint256 i = 0; i < LIB_ADDRS.length; i++) {
            vm.etch(LIB_ADDRS[i], vm.parseBytes(vm.readFile(LIB_HEX[i])));
        }
    }

    function _etchFacet(string memory hexFile) internal {
        _etchLibs();
        bytes memory code = vm.parseBytes(vm.readFile(hexFile));
        vm.etch(FACET, code);
        require(FACET.code.length == code.length, "facet bytecode etch failed");
    }

    // ------------------------------------------------------------------
    // Cross-function ECONOMIC INVARIANT hook (CONCRETE HARNESS FILLS THIS IN)
    // ------------------------------------------------------------------
    /// @notice Run the cross-function pair (e.g. deposit then withdraw) and
    ///         return TRUE iff the round-trip / composition / conservation
    ///         invariant HOLDS. This is the Step-4b human judgement: it must
    ///         exercise BOTH arms and assert a property that only holds when the
    ///         state one arm WRITES is exactly what the other arm CONSUMES.
    ///
    ///         Implementations MUST swallow reverts (try/catch the protocol
    ///         calls) and return FALSE on revert OR on a broken conservation
    ///         check, so the differential captures both failure modes (the
    ///         mutant may revert via a protocol invariant OR silently break
    ///         conservation).
    function _roundTripHolds() internal virtual returns (bool);

    // ------------------------------------------------------------------
    // Reusable kill oracle (NOT a fill-in)
    // ------------------------------------------------------------------
    /// @notice One-shot differential: the clean etched facet must satisfy the
    ///         invariant; the mutant etched facet must break it. This is the
    ///         mutation kill. A vacuous ``_roundTripHolds`` returning a constant
    ///         cannot flip and this reverts - false-green is impossible.
    function _assertMutantKilled() internal {
        _fork();
        _etchFacet(CLEAN_HEX);
        bool cleanOk = _roundTripHolds();
        require(cleanOk, "clean facet: invariant should HOLD (baseline faithful)");

        _fork();
        _etchFacet(MUTANT_HEX);
        bool mutantOk = _roundTripHolds();
        require(!mutantOk, "MUTANT NOT KILLED: mutated facet behaved like clean");
    }
}
