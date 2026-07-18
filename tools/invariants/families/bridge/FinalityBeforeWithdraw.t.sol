// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203-b (Invariant Library v2 — bridge family). It is a *candidate
// harness* only. The invariant below expresses a question for a
// fuzz/invariant runner; a passing run is suggestive, not conclusive,
// until the workspace evidence matrix carries a concrete status.
//
// Family: Bridge (cross-chain messaging with finality window).
// Property: withdrawal only after source-chain finality — a withdraw
//           (or unlock) on the destination chain cannot succeed while
//           the source-chain message is still within its challenge /
//           finality window. Pre-finality withdraw attempts must
//           revert; post-finality withdraw attempts may succeed.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the bridge contract exposing
// the finality-gated withdraw entry point (e.g. OptimismPortal,
// L2OutputOracle, OutboxRollup).
import "../src/{ContractName}.sol";

contract FinalityBeforeWithdraw is StdInvariant, Test {
    {ContractName} internal bridge;

    // Finality window in seconds — the delay required between the
    // source-chain message being proven and the withdrawal being
    // executable. Optimism's 7-day challenge window is the classic
    // example; tune per protocol.
    uint256 internal finalityWindow;

    // Per-withdrawal bookkeeping: when the source-chain proof was
    // submitted for the withdrawal the handler is currently targeting.
    // A value of 0 means "no pending withdrawal tracked this step".
    uint256 internal pendingProvenAt;
    bytes32 internal pendingWithdrawalId;

    function setUp() public virtual {
        // TODO: deploy `bridge`, set `finalityWindow` to the protocol's
        //       configured value, wire a handler that
        //         (a) proves a withdrawal and records (pendingProvenAt,
        //             pendingWithdrawalId),
        //         (b) optionally calls `warp` to move time forward, and
        //         (c) exercises the withdraw entry point.
        //       Call targetContract(address(bridge)).
    }

    function _tryWithdraw(bytes32 id) internal {
        // TODO: call the bridge's withdraw entry point with `id`.
        //       e.g. bridge.finalizeWithdrawalTransaction(id);
        id; // silence unused
    }

    /// Any withdraw whose proof has not yet cleared finality must
    /// revert. A successful pre-finality withdraw means the bridge
    /// trusted an unfinalized source-chain state — the canonical
    /// cross-chain soundness break.
    function invariant_withdraw_requires_finality() public {
        if (pendingWithdrawalId == bytes32(0)) return;
        if (pendingProvenAt == 0) return;
        uint256 earliestFinal = pendingProvenAt + finalityWindow;
        if (block.timestamp >= earliestFinal) {
            // Past-finality attempts are out of scope for this
            // invariant — only pre-finality rejection is asserted.
            return;
        }
        bool reverted;
        try this.__withdrawProbe(pendingWithdrawalId) {
            reverted = false;
        } catch {
            reverted = true;
        }
        assertTrue(
            reverted,
            "Bridge: withdraw succeeded before source-chain finality"
        );
    }

    function __withdrawProbe(bytes32 id) external {
        _tryWithdraw(id);
    }
}
