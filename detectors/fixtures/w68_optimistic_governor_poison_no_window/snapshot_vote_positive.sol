// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILiveVotes {
    function balanceOf(address account) external view returns (uint256);
    function getVotes(address account) external view returns (uint256);
}

// VULNERABLE: the proposal snapshot is the current block and votes read
// mutable current voting power, so a transient balance can poison outcome.
contract OptimisticGovernorSnapshotVotePoisonVulnerable {
    struct Proposal {
        uint256 startBlock;
        uint256 snapshotBlock;
        uint256 forVotes;
    }

    mapping(uint256 => Proposal) public proposals;
    ILiveVotes public token;
    uint256 public nextProposalId;

    constructor(ILiveVotes token_) {
        token = token_;
    }

    function propose() external returns (uint256 id) {
        id = ++nextProposalId;
        Proposal storage proposal = proposals[id];
        proposal.snapshotBlock = block.number;
        proposal.startBlock = block.number;
    }

    function castVote(uint256 id) external {
        Proposal storage proposal = proposals[id];
        require(block.number >= proposal.startBlock, "not started");
        uint256 weight = token.balanceOf(msg.sender);
        proposal.forVotes += weight;
    }
}
