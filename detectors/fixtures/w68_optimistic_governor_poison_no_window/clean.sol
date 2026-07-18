// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISelectorRegistry {
    function setSelector(bytes4 selector, address target) external;
}

// CLEAN: execution and installation both bind to unchallenged current
// proposal state before consuming the payload.
contract OptimisticGovernorPoisonSafe {
    struct Proposal {
        address target;
        bytes data;
        bytes4 selector;
        uint256 liveUntil;
        bytes32 proposalHash;
        bool challenged;
        bool canceled;
        bool executed;
        bool applied;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => bytes32) public expectedHash;
    ISelectorRegistry public registry;

    constructor(ISelectorRegistry registry_) {
        registry = registry_;
    }

    function executeProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        require(block.timestamp >= proposal.liveUntil, "window open");
        require(!proposal.challenged, "challenged");
        require(!proposal.canceled, "canceled");
        require(proposal.proposalHash == expectedHash[id], "stale hash");
        proposal.executed = true;
        (bool ok, ) = proposal.target.call(proposal.data);
        require(ok, "exec failed");
    }

    function applyProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        require(block.timestamp >= proposal.liveUntil, "window open");
        require(!proposal.challenged, "challenged");
        require(!proposal.canceled, "canceled");
        require(proposal.proposalHash == expectedHash[id], "stale hash");
        proposal.applied = true;
        registry.setSelector(proposal.selector, proposal.target);
    }
}
