// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only. It
// does not constitute evidence of any property until a runner actually
// executes it (e.g. `forge test --match-test invariant_` or the PR 107
// bounded fuzz runner) and records a concrete PASS / counterexample
// status in the workspace evidence matrix. Reading this file proves
// nothing on its own.
//
// Family: AMM (automated market maker, Uniswap-V2-shape pools).
// Property: constant-product k = reserve0 * reserve1 is non-decreasing
//           across user-callable entry points (swap/add/remove), i.e.
//           legitimate trades may hold k steady within rounding slack
//           and fees may grow k, but no sequence of external calls may
//           drive k below its pre-call value.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the AMM pair contract (e.g. UniswapV2Pair).
// TODO: if the target is a factory-produced pair, deploy a concrete pair in setUp.
import "../src/{ContractName}.sol";

contract ConstantProductInvariant is StdInvariant, Test {
    {ContractName} internal pair;

    // Slack tolerates one-wei rounding drift across a single swap; raise
    // this only after confirming the drift is a rounding artefact and
    // never a direction-asymmetric leak.
    uint256 internal constant ROUNDING_SLACK = 1;

    uint256 internal kPrev;

    function setUp() public virtual {
        // TODO: deploy `pair`, seed balances on both sides, approve the
        // pair, and call the protocol's `mint`/`sync` to establish a
        // non-degenerate (reserve0, reserve1).
        // TODO: targetContract(address(pair)) — and add a handler if
        // direct targeting lets the fuzzer call admin-only methods.
        // targetContract(address(pair));
        kPrev = _k();
    }

    function _k() internal view returns (uint256) {
        // TODO: call the contract's reserves getter (commonly
        // `getReserves()` returning (uint112, uint112, uint32)).
        // (uint112 r0, uint112 r1, ) = pair.getReserves();
        // return uint256(r0) * uint256(r1);
        return 0;
    }

    /// Core AMM claim: k never decreases past the rounding-slack floor.
    function invariant_k_non_decreasing() public {
        uint256 kNow = _k();
        assertGe(
            kNow + ROUNDING_SLACK,
            kPrev,
            "AMM: constant-product k decreased across call sequence"
        );
        // Ratchet forward so the check is per-step monotone, not just
        // against the initial value. Comment out if you want strict
        // floor-vs-initial semantics.
        if (kNow > kPrev) {
            kPrev = kNow;
        }
    }
}
