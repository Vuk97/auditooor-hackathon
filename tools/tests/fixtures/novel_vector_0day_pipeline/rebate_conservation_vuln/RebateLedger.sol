// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title RebateLedger - per-user maker-rebate accounting for a CLOB-style market
/// @notice This is the NOVEL-VECTOR / true-0-day proof-pipeline VULNERABLE
/// fixture. Unlike the `evm_zero_day_pipeline` ERC4626 fixture (a well-known
/// first-depositor / share-price-inflation class with a dedicated detector in
/// the corpus), the bug here is a TARGET-SPECIFIC conservation invariant that
/// only exists because THIS contract's own NatSpec declares it. There is no
/// pre-existing detector / known-class pattern that matches the violation: a
/// generic library would have to DERIVE the invariant from the spec text below,
/// then SEARCH the unmodified source for the path that breaks it.
///
/// ----------------------------------------------------------------------------
/// TARGET-SPECIFIC INVARIANT (the miner must derive this from the spec):
///
///   INV-REBATE-CONSERVATION:
///     At all times, the sum of every user's unclaimed `creditOf(user)` MUST be
///     less than or equal to `rebatePool`. The protocol can only ever credit a
///     rebate that it has already funded into `rebatePool`; credits are claims
///     against that pool and may never exceed it. Formally:
///
///         sum_over_users(creditOf(user)) <= rebatePool
///
///   This is a conservation law specific to this ledger's accounting model. It
///   is NOT a generic ERC20 supply check, NOT an ERC4626 share-price rule, NOT
///   reentrancy, NOT access control, NOT integer overflow (solc ^0.8 reverts on
///   those). It is a domain invariant readable only from this contract's spec.
/// ----------------------------------------------------------------------------
///
/// ROOT CAUSE OF THE VIOLATION (the synthetic 0-day):
///   `settleEpoch()` issues a maker's rebate credit but performs the
///   pool-sufficiency check (`totalCredits + rebate <= rebatePool`) ONLY inside
///   an epoch-rollover branch that is skipped on the FIRST settlement of a fresh
///   epoch for a maker. The credit is issued on every call; the standing-pool
///   ceiling check is conditional. On the boundary case (the first settle of a
///   new epoch for a maker) the ceiling check is skipped, so repeated
///   cross-epoch settles inflate total issued credits beyond the funded pool,
///   breaking INV-REBATE-CONSERVATION. The surplus is then over-claimable.
///
///   Accounting model: `rebatePool` is the standing funded ceiling. Credits are
///   claims against it; the pool is debited at `claim()`, not at settle, so the
///   invariant `totalCredits <= rebatePool` must hold at every settle. The bug
///   is the missing (conditional) ceiling check, not an arithmetic error.
///
///   No generic detector fires: there is no reentrancy, no unchecked math
///   (solc ^0.8 reverts overflow), no missing access modifier. The bug is ONLY
///   visible as a violation of the target-declared conservation law. This is
///   the definition of a novel vector / true 0-day in this plan: derive target
///   invariant -> search source for unknown violation -> prove it.
contract RebateLedger {
    address public immutable admin;

    /// @notice Standing funded ceiling. Credits are claims against this pool and
    /// (per INV-REBATE-CONSERVATION) must never in aggregate exceed it. The pool
    /// is debited at claim(), not at settle.
    uint256 public rebatePool;

    /// @notice Current settlement epoch.
    uint256 public epoch;

    /// @notice Last epoch for which a given maker was settled (replay guard).
    mapping(address => uint256) public lastSettledEpoch;

    /// @notice Unclaimed rebate credit per user. INVARIANT: the sum across all
    /// users must stay <= rebatePool.
    mapping(address => uint256) public creditOf;

    /// @notice Running aggregate of unclaimed credits issued (used by the
    /// harness/invariant to evaluate the conservation law without enumerating
    /// every user).
    uint256 public totalCredits;

    constructor() {
        admin = msg.sender;
    }

    /// @notice Admin raises the standing funded ceiling.
    function fundPool(uint256 amount) external {
        require(msg.sender == admin, "not admin");
        rebatePool += amount;
    }

    /// @notice Advance to the next settlement epoch.
    function rollEpoch() external {
        require(msg.sender == admin, "not admin");
        epoch += 1;
    }

    /// @notice Settle `maker`'s rebate for the current epoch.
    /// @dev VULNERABLE: the pool-sufficiency ceiling check is gated behind the
    /// `lastSettledEpoch` rollover branch, so it is SKIPPED on the first settle
    /// after a rollEpoch(). The credit is issued unconditionally. Repeated
    /// cross-epoch settles therefore push totalCredits past rebatePool,
    /// violating INV-REBATE-CONSERVATION (totalCredits <= rebatePool).
    function settleEpoch(address maker, uint256 rebate) external {
        require(msg.sender == admin, "not admin");
        require(rebate > 0, "zero rebate");

        // Ceiling check: only runs when the maker was already current this
        // epoch, i.e. it is SKIPPED on the first settle after a rollEpoch().
        // This conditional guard is the synthetic novel-vector bug.
        if (lastSettledEpoch[maker] == epoch) {
            require(totalCredits + rebate <= rebatePool, "exceeds pool");
        }

        // Credit path: ALWAYS runs.
        creditOf[maker] += rebate;
        totalCredits += rebate;
        lastSettledEpoch[maker] = epoch;
    }

    /// @notice Claim accumulated rebate credit; debits the standing pool.
    function claim() external returns (uint256 paid) {
        paid = creditOf[msg.sender];
        require(paid > 0, "nothing to claim");
        creditOf[msg.sender] = 0;
        totalCredits -= paid;
        // Over-claim is possible because totalCredits was allowed to exceed
        // rebatePool by the skipped ceiling check.
        rebatePool -= paid;
    }
}
