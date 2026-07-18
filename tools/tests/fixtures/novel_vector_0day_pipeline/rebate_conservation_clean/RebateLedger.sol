// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title RebateLedger - per-user maker-rebate accounting for a CLOB-style market
/// @notice NOVEL-VECTOR / true-0-day proof-pipeline NEGATIVE-CONTROL (clean)
/// fixture. Identical spec and identical PoC to the sibling
/// `rebate_conservation_vuln/RebateLedger.sol`, with the single accounting bug
/// fixed. The target-specific conservation invariant HOLDS here, so the same
/// invariant harness that flags the vulnerable variant must PASS on this one.
///
/// ----------------------------------------------------------------------------
/// TARGET-SPECIFIC INVARIANT (unchanged from the vulnerable variant's spec):
///
///   INV-REBATE-CONSERVATION:
///     sum_over_users(creditOf(user)) <= rebatePool
///
///   A domain-specific conservation law, not a generic detector class.
/// ----------------------------------------------------------------------------
///
/// FIX: `settleEpoch()` runs the standing-pool ceiling check
/// (`totalCredits + rebate <= rebatePool`) UNCONDITIONALLY on every settle,
/// regardless of epoch-rollover state. The epoch replay guard is decoupled from
/// the ceiling check. With the ceiling enforced on every credit issuance,
/// totalCredits can never exceed rebatePool, so INV-REBATE-CONSERVATION holds
/// for every reachable state. The identical PoC that breaks the vulnerable
/// variant passes here.
contract RebateLedger {
    address public immutable admin;

    uint256 public rebatePool;
    uint256 public epoch;
    mapping(address => uint256) public lastSettledEpoch;
    mapping(address => uint256) public creditOf;
    uint256 public totalCredits;

    constructor() {
        admin = msg.sender;
    }

    function fundPool(uint256 amount) external {
        require(msg.sender == admin, "not admin");
        rebatePool += amount;
    }

    function rollEpoch() external {
        require(msg.sender == admin, "not admin");
        epoch += 1;
    }

    /// @notice Settle `maker`'s rebate for the current epoch.
    /// @dev FIXED: the standing-pool ceiling check runs on EVERY settle, not
    /// only inside the epoch-rollover branch. The replay guard is separate from
    /// the conservation check.
    function settleEpoch(address maker, uint256 rebate) external {
        require(msg.sender == admin, "not admin");
        require(rebate > 0, "zero rebate");

        // Ceiling check runs unconditionally -> conservation preserved.
        require(totalCredits + rebate <= rebatePool, "exceeds pool");

        creditOf[maker] += rebate;
        totalCredits += rebate;
        lastSettledEpoch[maker] = epoch;
    }

    function claim() external returns (uint256 paid) {
        paid = creditOf[msg.sender];
        require(paid > 0, "nothing to claim");
        creditOf[msg.sender] = 0;
        totalCredits -= paid;
        // Safe: totalCredits <= rebatePool was maintained at every settle.
        rebatePool -= paid;
    }
}
