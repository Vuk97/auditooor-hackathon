// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only —
// a skeleton the protocol-specific setUp must complete before any
// execution. It does not constitute evidence of any property until a
// runner (forge invariant / PR 107 fuzz runner) records a concrete
// status in the workspace evidence matrix.
//
// Family: AMM (Uniswap-V2-shape pools).
// Property: a raw ERC20 transfer into the pair (a "donation") must
//           not let an attacker steal from an honest LP. Concretely,
//           an attacker who (a) donates tokens directly to the pair
//           then (b) interacts via the normal entry points can never
//           end up with strictly more value than they started with.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the target pair / pool contract.
import "../src/{ContractName}.sol";

contract DonationAttackResistance is StdInvariant, Test {
    {ContractName} internal pair;

    address internal attacker = address(0xA77ACCE7);
    address internal honestLp = address(0xA11CE);

    // Snapshotted attacker-value baseline, denominated in the pair's
    // token0-equivalent. Pre-attack this must be the sum of (token0
    // held) + (token1 held * spot) + (LP shares * share-price).
    uint256 internal attackerValueT0Before;

    function setUp() public virtual {
        // TODO: deploy `pair`, seed honest LP liquidity, and set
        //       attackerValueT0Before to attacker's starting value.
        // TODO: targetContract(address(pair)) + handler that lets the
        //       fuzzer donate (raw transfer) and then call swap/mint/burn.
    }

    function _valueInToken0(address who) internal view returns (uint256) {
        // TODO: implement — read (t0 balance, t1 balance, LP shares) for
        // `who`, convert t1 and LP to token0-equivalent using the
        // current pool state (not an external oracle).
        return 0;
    }

    /// Post-interaction attacker value, including any donated tokens
    /// the pair refunded back, must not exceed the pre-attack value.
    function invariant_donation_does_not_profit_attacker() public {
        uint256 after_ = _valueInToken0(attacker);
        assertLe(
            after_,
            attackerValueT0Before,
            "AMM: donation-attack path increased attacker value"
        );
    }
}
