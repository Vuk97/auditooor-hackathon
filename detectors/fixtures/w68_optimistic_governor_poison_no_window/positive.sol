// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISelectorRegistry {
    function setSelector(bytes4 selector, address target) external;
}

// VULNERABLE: proposal state is consumed for execution or installation
// without checking any challenge window, cancel flag, or freshness hash.
contract OptimisticGovernorPoisonVulnerable {
    struct Proposal {
        address target;
        bytes data;
        bytes4 selector;
        bool executed;
        bool applied;
    }

    mapping(uint256 => Proposal) public proposals;
    ISelectorRegistry public registry;

    constructor(ISelectorRegistry registry_) {
        registry = registry_;
    }

    function executeProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        proposal.executed = true;
        (bool ok, ) = proposal.target.call(proposal.data);
        require(ok, "exec failed");
    }

    function applyProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        proposal.applied = true;
        registry.setSelector(proposal.selector, proposal.target);
    }
}
