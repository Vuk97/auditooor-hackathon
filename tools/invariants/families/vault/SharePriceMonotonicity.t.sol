// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only. It
// is not evidence of correctness until a runner (forge invariant /
// PR 107 fuzz runner) executes the harness and records a concrete
// status against a specific deployed target in the evidence matrix.
//
// Family: ERC4626 / Vault.
// Property: share-price monotonicity — the share-to-asset ratio
//           measured via `convertToAssets(1e18)` (or equivalently
//           `previewRedeem`) never strictly decreases across calls
//           to deposit / mint / withdraw / redeem. Yield or the
//           donation of underlying may raise it; user actions at
//           honest rounding may hold it; but nothing may inflate
//           shares faster than assets and lower the ratio.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the ERC4626 vault under test.
import "../src/{ContractName}.sol";

contract SharePriceMonotonicity is StdInvariant, Test {
    {ContractName} internal vault;

    uint256 internal lastAssetsPerShare;

    // Raise only if the vault is documented to round down share price
    // on a specific entry (e.g. a withdraw-with-slippage path). Slack
    // hides real bugs; keep tight.
    uint256 internal constant ROUNDING_SLACK = 0;

    function setUp() public virtual {
        // TODO: deploy `vault`, seed underlying, prime first deposit
        //       (so share price is defined and not 1:1 by accident),
        //       call targetContract(address(vault)) + a handler that
        //       exercises deposit / mint / withdraw / redeem.
        lastAssetsPerShare = _assetsPerShare();
    }

    function _assetsPerShare() internal view returns (uint256) {
        // TODO: return vault.convertToAssets(1e18). Guard against the
        //       zero-supply case by returning a sentinel the invariant
        //       ignores until the first deposit.
        return 0;
    }

    /// Assets-per-share never regresses. Catches the classic ERC4626
    /// first-deposit inflation attack (share price goes up then a
    /// second path brings it back down) and rounding-asymmetry bugs.
    function invariant_share_price_non_decreasing() public {
        uint256 now_ = _assetsPerShare();
        if (now_ == 0) return; // pre-first-deposit sentinel
        assertGe(
            now_ + ROUNDING_SLACK,
            lastAssetsPerShare,
            "Vault: share price regressed"
        );
        if (now_ > lastAssetsPerShare) {
            lastAssetsPerShare = now_;
        }
    }
}
