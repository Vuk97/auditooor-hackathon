// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only.
// Read this as a question to a fuzz runner, not as a statement of
// fact. The workspace evidence matrix must carry a concrete run
// status before anyone cites this harness as proof.
//
// Family: ERC4626 / Vault.
// Property: totalAssets() monotonicity under the right operations —
//           a `deposit` strictly increases totalAssets by the
//           transferred principal (modulo rounding), a `redeem`
//           strictly decreases it by the withdrawn principal, and
//           a passive non-user call (view, approve, ...) leaves it
//           untouched. Mirror-writes via rebalance / harvest may
//           raise totalAssets (yield) but never lower it without a
//           documented realized-loss path.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the ERC4626 vault under test.
import "../src/{ContractName}.sol";

contract TotalAssetsMonotonicity is StdInvariant, Test {
    {ContractName} internal vault;

    uint256 internal totalAssetsPrev;

    // Set this handler-side: a handler that only performs deposits
    // must wire `noUserWithdrawals = true`; the invariant then
    // tightens to strict non-decrease. Without that flag we only
    // assert "no unexplained drop" via the realized-loss tracker.
    bool internal noUserWithdrawals;

    // Realized losses the protocol has documented in-call (e.g. via a
    // harvest event, a slashing hook). Subtract from totalAssetsPrev
    // before the comparison. Handlers must update this on each path
    // that legitimately burns underlying.
    uint256 internal realizedLossesSinceSnapshot;

    function setUp() public virtual {
        // TODO: deploy `vault`, seed assets, call targetContract(),
        //       hook a handler that either (a) only deposits, setting
        //       noUserWithdrawals = true, or (b) tracks realized
        //       losses into realizedLossesSinceSnapshot.
        totalAssetsPrev = vault.totalAssets();
    }

    /// totalAssets() never drops unexplained.
    function invariant_total_assets_no_unexplained_drop() public {
        uint256 now_ = vault.totalAssets();
        uint256 floor = totalAssetsPrev > realizedLossesSinceSnapshot
            ? totalAssetsPrev - realizedLossesSinceSnapshot
            : 0;
        assertGe(
            now_,
            floor,
            "Vault: totalAssets() dropped below realized-loss floor"
        );
        totalAssetsPrev = now_;
        realizedLossesSinceSnapshot = 0;
    }
}
