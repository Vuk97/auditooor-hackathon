// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: quorum sums participating votes, succeeded requires majority.
contract CleanGovernor {
    struct ProposalVote {
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
    }

    mapping(uint256 => ProposalVote) public proposalVotes;
    uint256 public quorumThreshold;

    function quorum() public view returns (uint256) {
        return quorumThreshold;
    }

    // OZ-style: quorum counts for + abstain participating votes.
    function _quorumReached(uint256 proposalId) external view returns (bool) {
        ProposalVote memory v = proposalVotes[proposalId];
        return v.forVotes + v.abstainVotes >= quorum();
    }

    // Succeeded requires the FOR side to outnumber AGAINST.
    function _voteSucceeded(uint256 proposalId) external view returns (bool) {
        ProposalVote memory v = proposalVotes[proposalId];
        return v.forVotes > v.againstVotes;
    }

    function state(uint256 proposalId) external view returns (uint256) {
        ProposalVote memory v = proposalVotes[proposalId];
        // Both predicates must hold.
        if (v.forVotes + v.abstainVotes >= quorum() && v.forVotes > v.againstVotes) {
            return 4; // Succeeded
        }
        return 3; // Defeated
    }
}
