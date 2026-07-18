// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IProposalTarget {
    function install(bytes4 selector, address target) external;
}

contract OptimisticProposalWindowClean {
    struct Proposal {
        address target;
        bytes data;
        bytes4 selector;
        uint256 liveUntil;
        bytes32 proposalHash;
        bool challenged;
        bool canceled;
        bool consumed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => bytes32) public expectedHash;
    IProposalTarget public installer;

    constructor(IProposalTarget installer_) {
        installer = installer_;
    }

    function executeProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        require(block.timestamp >= proposal.liveUntil, "window open");
        require(!proposal.challenged, "challenged");
        require(!proposal.canceled, "canceled");
        require(proposal.proposalHash == expectedHash[id], "stale hash");
        proposal.consumed = true;
        (bool ok, ) = proposal.target.call(proposal.data);
        require(ok, "call failed");
    }

    function applyProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        require(block.timestamp >= proposal.liveUntil, "window open");
        require(!proposal.challenged, "challenged");
        require(!proposal.canceled, "canceled");
        require(proposal.proposalHash == expectedHash[id], "stale hash");
        proposal.consumed = true;
        installer.install(proposal.selector, proposal.target);
    }
}
