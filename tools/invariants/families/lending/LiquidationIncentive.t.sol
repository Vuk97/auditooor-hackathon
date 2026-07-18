// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only.
// The invariant_ below describes a question to be answered by a fuzz
// runner; a passing run is a weak positive signal, not proof of
// economic correctness. The evidence matrix is the source of truth.
//
// Family: Lending protocol.
// Property: liquidation-incentive non-negative profit — a successful
//           `liquidate(borrower, collateral, repayAmount)` must
//           hand the liquidator at least `repayAmount * (1 + incentive)`
//           worth of collateral at pool-oracle prices. If the pool's
//           incentive calculation rounds the wrong way (or an
//           oracle quirk brings the collateral valuation below the
//           debt they repaid), liquidators refuse to liquidate and
//           the protocol accumulates bad debt.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the lending-pool contract.
import "../src/{ContractName}.sol";

contract LiquidationIncentive is StdInvariant, Test {
    {ContractName} internal pool;

    address internal liquidator = address(0xCAFE);
    address internal borrower = address(0xBAD);

    // Incentive in bps: 10500 = +5% collateral bonus. Match the
    // protocol's configured value. The invariant asserts the
    // realized liquidator profit is >= 0, i.e. collateral received
    // valued at oracle >= repayAmount.
    uint256 internal incentiveBps;

    // Snapshotted pre-liquidation balances (asset, value-in-quote).
    uint256 internal liquidatorQuoteBefore;
    uint256 internal repayAmountLastCall;

    function setUp() public virtual {
        // TODO: deploy `pool`, open a borrower position that is
        //       underwater, prime liquidator balances, set incentiveBps
        //       to the protocol's value, wire a handler that
        //       snapshots liquidatorQuoteBefore + repayAmountLastCall
        //       immediately before each liquidate() call.
    }

    function _quoteBalanceOf(address who) internal view returns (uint256) {
        // TODO: sum every asset `who` holds, valued via pool's oracle.
        who; // silence unused
        return 0;
    }

    /// After every liquidation step the handler executed, the
    /// liquidator's value-in-quote gained >= the debt they repaid.
    /// A failure means the protocol underpays liquidators — bad-debt
    /// formation risk.
    function invariant_liquidator_non_negative_profit() public {
        if (repayAmountLastCall == 0) return; // no liquidation this step
        uint256 after_ = _quoteBalanceOf(liquidator);
        uint256 gained = after_ > liquidatorQuoteBefore
            ? after_ - liquidatorQuoteBefore
            : 0;
        assertGe(
            gained,
            repayAmountLastCall,
            "Lending: liquidator profit negative — incentive misconfigured"
        );
        // Reset so subsequent steps don't double-count.
        repayAmountLastCall = 0;
    }
}
