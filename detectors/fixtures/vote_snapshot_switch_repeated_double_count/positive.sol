// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteSnapshotSwitchRepeatedDoubleCountPositive {
    struct Proposal {
        uint256 startBlock;
        uint256 creationBlock;
    }

    uint256 public proposalCount;
    uint256 public voteSnapshotBlockSwitchProposalId;
    mapping(uint256 => Proposal) public proposals;

    event VoteSnapshotBlockSwitchProposalIdSet(uint256 oldValue, uint256 newValue);

    function createProposal(uint256 startBlock, uint256 creationBlock) external {
        proposalCount += 1;
        proposals[proposalCount] = Proposal(startBlock, creationBlock);
    }

    function setVoteSnapshotBlockSwitchProposalId() external {
        uint256 oldVoteSnapshotBlockSwitchProposalId = voteSnapshotBlockSwitchProposalId;
        uint256 newVoteSnapshotBlockSwitchProposalId = proposalCount + 1;
        voteSnapshotBlockSwitchProposalId = newVoteSnapshotBlockSwitchProposalId;
        emit VoteSnapshotBlockSwitchProposalIdSet(
            oldVoteSnapshotBlockSwitchProposalId,
            newVoteSnapshotBlockSwitchProposalId
        );
    }
}
