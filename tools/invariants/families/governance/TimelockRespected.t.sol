// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203-b (Invariant Library v2 — governance family). It is a
// *candidate harness* only. It does not constitute evidence of any
// property until a runner actually executes it and records a concrete
// PASS / counterexample status in the workspace evidence matrix.
//
// Family: Governance / Timelock.
// Property: an action scheduled with a `minDelay` cannot execute
//           before `block.timestamp >= scheduledAt + minDelay`. Any
//           execute() call that runs before its unlock time must
//           revert, regardless of caller role or operation type.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the timelock contract (e.g.
// TimelockController, Governor's timelock).
import "../src/{ContractName}.sol";

contract TimelockRespected is StdInvariant, Test {
    {ContractName} internal timelock;

    // Per-operation bookkeeping. The handler must, on each schedule()
    // call, push (id, scheduledAt, delay) so the invariant has a
    // candidate to probe.
    bytes32 internal pendingId;
    uint256 internal pendingScheduledAt;
    uint256 internal pendingDelay;

    function setUp() public virtual {
        // TODO: deploy `timelock`, grant handler the proposer role,
        //       call targetContract(address(timelock)) + wire a handler
        //       that
        //         (a) schedules an operation, records (pendingId,
        //             pendingScheduledAt, pendingDelay),
        //         (b) optionally warps time forward,
        //         (c) attempts execute().
    }

    function _tryExecute(bytes32 id) internal {
        // TODO: call the timelock's execute entry point.
        //       e.g. timelock.execute(target, value, data, predecessor, salt);
        id; // silence unused
    }

    /// An execute() whose scheduled unlock time has not yet arrived
    /// must revert. If this invariant fails, the timelock is not
    /// enforcing the delay — a direct governance-bypass break.
    function invariant_timelock_enforced() public {
        if (pendingId == bytes32(0)) return;
        uint256 unlockAt = pendingScheduledAt + pendingDelay;
        if (block.timestamp >= unlockAt) {
            // Post-unlock execution is out of scope for this invariant.
            return;
        }
        bool reverted;
        try this.__executeProbe(pendingId) {
            reverted = false;
        } catch {
            reverted = true;
        }
        assertTrue(
            reverted,
            "Governance: timelock execute succeeded before minDelay elapsed"
        );
    }

    function __executeProbe(bytes32 id) external {
        _tryExecute(id);
    }
}
