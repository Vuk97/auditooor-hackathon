// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only.
// It asserts a structural bound; it does not prove the vault is safe
// until a runner confirms no counterexample exists against a real
// deployed target. The evidence matrix is the source of truth, not
// this file.
//
// Family: ERC4626 / Vault.
// Property: redemption never exceeds balance — for every caller
//           `who` and every call to `redeem(shares, receiver, who)`
//           the returned `assets` must be <= `vault.totalAssets()`
//           and must never grant the caller more than
//           `convertToAssets(balanceOf(who))`. This catches both
//           the "redeem more shares than you own" bug and the
//           "redeem pays out more assets than the vault holds"
//           solvency bug.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the ERC4626 vault under test.
import "../src/{ContractName}.sol";

contract RedemptionBounds is StdInvariant, Test {
    {ContractName} internal vault;

    // Population of addresses the handler is allowed to act as. Must
    // cover every address that can ever hold shares.
    address[] internal users;

    function setUp() public virtual {
        // TODO: deploy `vault`, seed users, populate `users`, call
        //       targetContract(address(vault)) + a handler that wraps
        //       deposit/withdraw/redeem with vm.prank(users[i]).
    }

    /// Every user's share balance, valued in assets, is <= totalAssets.
    /// If this fails, the vault is paying more than it owns to a caller
    /// — a direct solvency break.
    function invariant_redemption_never_exceeds_vault_balance() public {
        uint256 ta = vault.totalAssets();
        for (uint256 i = 0; i < users.length; i++) {
            uint256 shares = vault.balanceOf(users[i]);
            if (shares == 0) continue;
            uint256 payable_ = vault.convertToAssets(shares);
            assertLe(
                payable_,
                ta,
                "Vault: user redemption exceeds vault totalAssets"
            );
        }
    }

    /// Sum of every user's redemption-value is <= totalAssets.
    /// Catches the case where each user individually passes the above
    /// check but the aggregate exceeds the vault (i.e. shares were
    /// minted without corresponding assets).
    function invariant_aggregate_redemption_bounded() public {
        uint256 sumAssets;
        for (uint256 i = 0; i < users.length; i++) {
            uint256 shares = vault.balanceOf(users[i]);
            if (shares == 0) continue;
            sumAssets += vault.convertToAssets(shares);
        }
        assertLe(
            sumAssets,
            vault.totalAssets(),
            "Vault: sum of user redemptions exceeds totalAssets"
        );
    }
}
