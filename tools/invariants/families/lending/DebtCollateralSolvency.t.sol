// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only.
// The invariant_ functions below express questions the fuzz/invariant
// runner must answer against a concrete deployment before any claim
// of solvency is made. Nothing in this file, by itself, is proof.
//
// Family: Lending protocol (Compound / Aave / morpho-shape pools).
// Property: debt-collateral solvency — the pool is solvent iff
//           total-collateral-value (in pool's quote) >= total-debt-
//           value across every (user, market) pair at all times.
//           Any sequence of borrow / repay / liquidate / mint calls
//           that drives total-debt above total-collateral is a
//           direct break.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the lending-pool contract.
import "../src/{ContractName}.sol";

contract DebtCollateralSolvency is StdInvariant, Test {
    {ContractName} internal pool;

    // TODO: populate `users` with every address a handler can act as,
    // and `assets` with every collateral and debt market the pool
    // supports.
    address[] internal users;
    address[] internal assets;

    function setUp() public virtual {
        // TODO: deploy `pool`, seed supply, open baseline positions,
        //       populate users + assets, call targetContract(pool) +
        //       wire a handler that brackets supply/borrow/repay/
        //       liquidate paths.
    }

    function _collateralValue(address user) internal view returns (uint256) {
        // TODO: call pool.getAccountLiquidity(user) or the equivalent
        //       per-protocol accessor and return the collateral side
        //       in the pool's quote asset.
        return 0;
    }

    function _debtValue(address user) internal view returns (uint256) {
        // TODO: return borrowBalanceStored summed across `assets` and
        //       converted to the pool's quote asset with the pool's
        //       own oracle (not an external price).
        return 0;
    }

    /// Protocol-level solvency: aggregate collateral >= aggregate debt.
    /// If this fails, the pool contains more debt than it can settle.
    function invariant_pool_solvent() public {
        uint256 totalC;
        uint256 totalD;
        for (uint256 i = 0; i < users.length; i++) {
            totalC += _collateralValue(users[i]);
            totalD += _debtValue(users[i]);
        }
        assertGe(totalC, totalD, "Lending: pool debt exceeds collateral");
    }
}
