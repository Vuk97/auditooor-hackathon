// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203-b (Invariant Library v2 — governance family). It is a
// *candidate harness* only. A passing run is suggestive, not
// conclusive, until the workspace evidence matrix carries a concrete
// status from an actual runner.
//
// Family: Governance (OpenZeppelin-Governor-shape proposals).
// Property: a proposal cannot transition into an Executable state
//           (Succeeded / Queued / Executed) unless accumulated
//           support (forVotes + optionally abstain, depending on
//           quorum mode) is at least the configured quorum at the
//           snapshot block. Any proposal marked Succeeded with
//           support < quorum is a direct governance-bypass break.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the governor contract exposing
// state()/proposalVotes()/quorum().
import "../src/{ContractName}.sol";

contract QuorumEnforced is StdInvariant, Test {
    {ContractName} internal governor;

    // Tracked proposal ids created by the handler. The invariant
    // walks this list each step and checks every Succeeded proposal
    // carries support >= quorum(snapshotBlock).
    uint256[] internal proposalIds;

    // Proposal state values mirroring OZ Governor's IGovernor.ProposalState.
    // Adjust if the target uses a different enum order.
    uint8 internal constant STATE_SUCCEEDED = 4;
    uint8 internal constant STATE_QUEUED = 5;
    uint8 internal constant STATE_EXECUTED = 7;

    function setUp() public virtual {
        // TODO: deploy `governor`, wire voting-token distribution,
        //       call targetContract(address(governor)) + a handler that
        //         (a) creates proposals, pushes id into proposalIds,
        //         (b) casts votes (with various weights) via castVote,
        //         (c) warps through voting delay + period.
    }

    function _stateOf(uint256 id) internal view returns (uint8) {
        // TODO: return uint8(governor.state(id));
        id; // silence unused
        return 0;
    }

    function _supportOf(uint256 id) internal view returns (uint256 forVotes) {
        // TODO: (uint256 against, uint256 for_, uint256 abstain) =
        //        governor.proposalVotes(id); return for_ (plus abstain
        //        if the quorum policy counts it).
        id; // silence unused
        return 0;
    }

    function _quorumAt(uint256 id) internal view returns (uint256) {
        // TODO: uint256 snap = governor.proposalSnapshot(id);
        //       return governor.quorum(snap);
        id; // silence unused
        return 0;
    }

    /// Every proposal the governor reports as Succeeded / Queued /
    /// Executed must have accumulated support >= quorum at its
    /// snapshot block. A violation is a direct bypass of the
    /// governor's quorum gate.
    function invariant_quorum_gate() public {
        for (uint256 i = 0; i < proposalIds.length; i++) {
            uint256 id = proposalIds[i];
            uint8 st = _stateOf(id);
            if (
                st != STATE_SUCCEEDED &&
                st != STATE_QUEUED &&
                st != STATE_EXECUTED
            ) continue;
            uint256 support = _supportOf(id);
            uint256 q = _quorumAt(id);
            assertGe(
                support,
                q,
                "Governance: proposal reached executable state below quorum"
            );
        }
    }
}
