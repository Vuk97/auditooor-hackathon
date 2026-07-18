// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPastVotes {
    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
}

// CLEAN: the proposal binds voting power to a past block and castVote reads
// the immutable snapshot instead of current balances.
contract OptimisticGovernorSnapshotVotePoisonSafe {
    struct Proposal {
        uint256 startBlock;
        uint256 snapshotBlock;
        uint256 forVotes;
    }

    mapping(uint256 => Proposal) public proposals;
    IPastVotes public token;
    uint256 public nextProposalId;
    uint256 public votingDelay = 1;

    constructor(IPastVotes token_) {
        token = token_;
    }

    function propose() external returns (uint256 id) {
        id = ++nextProposalId;
        Proposal storage proposal = proposals[id];
        proposal.snapshotBlock = block.number - 1;
        proposal.startBlock = block.number + votingDelay;
    }

    function castVote(uint256 id) external {
        Proposal storage proposal = proposals[id];
        require(block.number >= proposal.startBlock, "not started");
        uint256 weight = token.getPastVotes(msg.sender, proposal.snapshotBlock);
        proposal.forVotes += weight;
    }
}
