// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: optimistic governor executes a queued proposal without
// re-checking that the dispute/liveness window expired unchallenged.
contract OptimisticGovernorPoisonVulnerable {
    struct Proposal { address target; bytes data; bool executed; }
    mapping(uint256 => Proposal) public proposals;

    function executeProposal(uint256 id) external {
        Proposal storage p = proposals[id];
        p.executed = true;
        (bool ok, ) = p.target.call(p.data);
        require(ok, "exec failed");
    }
}
