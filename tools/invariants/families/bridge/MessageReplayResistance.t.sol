// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203-b (Invariant Library v2 — bridge family). It is a *candidate
// harness* only. It does not constitute evidence of any property until
// a runner actually executes it (e.g. `forge test --match-test
// invariant_` or the PR 107 bounded fuzz runner) and records a
// concrete PASS / counterexample status in the workspace evidence
// matrix. Reading this file proves nothing on its own.
//
// Family: Bridge (cross-chain messaging / lock-and-mint bridges).
// Property: message-replay resistance — a cross-chain message that
//           has already been consumed on the destination chain must
//           never be consumed again. Re-submitting a stored consumed
//           message (same nonce / messageId / proof) must revert on
//           every subsequent attempt regardless of caller.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the destination-chain message
// consumer (e.g. L2CrossDomainMessenger, Inbox, Endpoint).
import "../src/{ContractName}.sol";

contract MessageReplayResistance is StdInvariant, Test {
    {ContractName} internal bridge;

    // Seen-message ledger. On every handler-observed successful
    // consume, the handler must insert (messageId => payload bytes)
    // here. The invariant below replays one and asserts revert.
    mapping(bytes32 => bytes) internal consumedPayload;
    bytes32[] internal consumedIds;

    // Most recent id the handler saw consumed — the invariant targets
    // this one so the fuzzer has a fresh replay candidate each step.
    bytes32 internal lastConsumedId;

    function setUp() public virtual {
        // TODO: deploy `bridge`, wire the source-chain mock/relayer,
        //       call targetContract(address(bridge)) + a handler that
        //       (a) crafts a valid message, (b) calls the consume path
        //       (e.g. relayMessage / processMessage / executeMessage),
        //       and (c) on success records (messageId, payload) into
        //       consumedPayload + sets lastConsumedId.
    }

    function _replay(bytes32 id, bytes memory payload) internal {
        // TODO: call the same consume entry point the handler uses,
        //       with the exact stored payload. The bridge must revert.
        // bridge.processMessage(id, payload);
        id; // silence unused
        payload;
    }

    /// Re-submitting a message that has already been consumed must
    /// revert. If the bridge accepts the replay — mint/unlock fires
    /// twice for one source-chain lock — that is a direct double-spend.
    function invariant_replay_protected() public {
        if (lastConsumedId == bytes32(0)) return; // no message yet
        bytes memory payload = consumedPayload[lastConsumedId];
        if (payload.length == 0) return; // handler didn't record one
        bool reverted;
        try this.__replayProbe(lastConsumedId, payload) {
            reverted = false;
        } catch {
            reverted = true;
        }
        assertTrue(
            reverted,
            "Bridge: consumed message accepted on replay (double-spend)"
        );
    }

    // External wrapper so we can catch reverts from within the
    // invariant. Marked external to give try/catch a frame boundary.
    function __replayProbe(bytes32 id, bytes memory payload) external {
        _replay(id, payload);
    }
}
