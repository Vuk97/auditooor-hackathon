// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only.
// Treat any `invariant_*` pass below as suggestive, not conclusive,
// until a runner executes the harness and records a concrete status
// in the workspace evidence matrix.
//
// Family: AMM (Uniswap-V2-shape pools).
// Property: LP-share conservation — the sum of LP balances across
//           tracked holders equals the pair's `totalSupply()`. Any
//           call that mints or burns LP tokens must update both
//           sides in the same frame.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the AMM pair / pool contract.
import "../src/{ContractName}.sol";

contract LPShareConservation is StdInvariant, Test {
    {ContractName} internal pair;

    // TODO: populate holders in setUp — include every address the
    // handler is allowed to mint LP to (LPs, the pair itself if it
    // holds locked-liquidity shares, address(0xdead), etc.).
    address[] internal holders;

    function setUp() public virtual {
        // TODO: deploy `pair`, seed liquidity, populate `holders` with
        //       every address that can hold LP, call targetContract().
    }

    function _sumLpBalances() internal view returns (uint256 sum) {
        for (uint256 i = 0; i < holders.length; i++) {
            // TODO: cast `pair` to IERC20 (pair is its own LP token in
            //       UniV2-style AMMs) and read balanceOf.
            // sum += IERC20(address(pair)).balanceOf(holders[i]);
        }
    }

    /// Sum of LP balances across tracked holders equals totalSupply().
    /// If a path mints LP without updating supply (or vice versa),
    /// this assertion flags it.
    function invariant_lp_shares_equal_total_supply() public {
        uint256 sum = _sumLpBalances();
        // TODO: cast `pair` to expose totalSupply() (IERC20).
        // uint256 supply = IERC20(address(pair)).totalSupply();
        uint256 supply = 0;
        assertEq(sum, supply, "AMM: LP holder sum != totalSupply()");
    }
}
