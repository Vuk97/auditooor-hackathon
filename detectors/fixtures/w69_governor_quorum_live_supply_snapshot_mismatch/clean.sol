// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenVotesClean {
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
    function getPastTotalSupply(uint256 timepoint) external view returns (uint256);
}

contract W69GovernorQuorumLiveSupplySnapshotMismatchClean {
    struct Proposal {
        uint256 snapshotBlock;
        uint256 forVotes;
    }

    mapping(uint256 => Proposal) public proposals;
    ITokenVotesClean public token;
    uint256 public quorumBps = 400;

    constructor(ITokenVotesClean token_) {
        token = token_;
    }

    function propose(uint256 proposalId) external {
        proposals[proposalId].snapshotBlock = block.number - 1;
    }

    function castVote(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        uint256 weight = token.getPastVotes(msg.sender, proposal.snapshotBlock);
        proposal.forVotes += weight;
    }

    function quorum(uint256 proposalId) public view returns (uint256) {
        Proposal storage proposal = proposals[proposalId];
        return (token.getPastTotalSupply(proposal.snapshotBlock) * quorumBps) / 10000;
    }
}
