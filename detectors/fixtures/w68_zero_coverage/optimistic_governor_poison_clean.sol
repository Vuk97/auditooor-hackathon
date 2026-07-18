// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: execution checks the liveness window and the unchallenged flag.
contract OptimisticGovernorPoisonSafe {
    struct Proposal { address target; bytes data; bool executed; uint256 liveUntil; bool challenged; }
    mapping(uint256 => Proposal) public proposals;

    function executeProposal(uint256 id) external {
        Proposal storage p = proposals[id];
        require(block.timestamp >= p.liveUntil, "window open");
        require(!p.challenged, "challenged");
        p.executed = true;
        (bool ok, ) = p.target.call(p.data);
        require(ok, "exec failed");
    }
}
