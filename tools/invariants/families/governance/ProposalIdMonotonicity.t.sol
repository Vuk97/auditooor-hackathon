// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203-b (Invariant Library v2 — governance family). It is a
// *candidate harness* only. Treat a pass as a weak positive signal,
// not proof, until a runner records a concrete status in the
// workspace evidence matrix.
//
// Family: Governance.
// Property: proposal-id monotonicity — every successful propose()
//           call yields a strictly greater id than the previous one,
//           and no id is reused. A non-monotone id sequence is the
//           usual symptom of a proposal-overwrite bug (hash-based ids
//           with a salt collision, or a counter not incremented on
//           the reverted path).
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the governor contract exposing
// the propose() entry point.
import "../src/{ContractName}.sol";

contract ProposalIdMonotonicity is StdInvariant, Test {
    {ContractName} internal governor;

    // Ordered log of every id the handler observed from a successful
    // propose() call. The invariant below walks this and asserts the
    // strictly-increasing + uniqueness property.
    uint256[] internal observedIds;
    mapping(uint256 => bool) internal seen;

    function setUp() public virtual {
        // TODO: deploy `governor`, wire voting power, call
        //       targetContract(address(governor)) + a handler that
        //       spams propose() with varying (targets, values,
        //       calldatas, description) tuples and, on success,
        //       pushes the returned id into observedIds and sets
        //       seen[id] = true.
    }

    /// Handler-facing helper: call this from your `Handler.propose()`
    /// wrapper with the id returned by governor.propose(...). Keeps
    /// id-log maintenance in one place rather than duplicated across
    /// handlers.
    function _recordProposal(uint256 id) internal {
        // The contract-reuse check runs inside the invariant below;
        // here we only append — so the invariant sees the raw log,
        // including any duplicate the fuzzer exercised.
        observedIds.push(id);
    }

    /// Ids must be strictly increasing across the observation log
    /// and must never repeat. If ids are hash-derived (OZ Governor's
    /// keccak of proposal parameters), a repeat means the same
    /// proposal was re-created after being cancelled/expired — which
    /// is itself a governance-replay hazard if the original outcome
    /// can be reused.
    function invariant_ids_monotonic() public {
        for (uint256 i = 1; i < observedIds.length; i++) {
            assertGt(
                observedIds[i],
                observedIds[i - 1],
                "Governance: proposal id not strictly increasing"
            );
        }
        // Uniqueness check — separate pass so the message points at
        // the reuse explicitly rather than folding into the ordering
        // assertion above.
        uint256 n = observedIds.length;
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                assertTrue(
                    observedIds[i] != observedIds[j],
                    "Governance: proposal id reused across propose() calls"
                );
            }
        }
    }
}
