// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOZStyleVotesClean {
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
    function getPastTotalSupply(uint256 timepoint) external view returns (uint256);
}

contract W69GovernorQuorumLiveSupplySnapshotMismatchOZStyleClean {
    struct ProposalCore {
        uint256 voteStart;
        uint256 forVotes;
    }

    mapping(uint256 => ProposalCore) internal _proposals;
    IOZStyleVotesClean public token;
    uint256 public quorumNumerator = 4;

    constructor(IOZStyleVotesClean token_) {
        token = token_;
    }

    function propose(uint256 proposalId) external {
        _proposals[proposalId].voteStart = clock() - 1;
    }

    function clock() public view returns (uint48) {
        return uint48(block.number);
    }

    function proposalSnapshot(uint256 proposalId) public view returns (uint256) {
        return _proposals[proposalId].voteStart;
    }

    function castVote(uint256 proposalId) external {
        uint256 timepoint = proposalSnapshot(proposalId);
        uint256 weight = token.getPastVotes(msg.sender, timepoint);
        _proposals[proposalId].forVotes += weight;
    }

    function quorum(uint256 timepoint) public view returns (uint256) {
        return (token.getPastTotalSupply(timepoint) * quorumNumerator) / 100;
    }
}
