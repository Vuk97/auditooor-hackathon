// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: governance quorum / succeeded predicate reads the wrong side.
// Modeled on IQ AI H-01 (Code4rena 2025-01) — proposal can pass with
// ~4% voting power because `_quorumReached` compares `againstVotes`
// to quorum instead of the sum of participating votes.
contract VulnGovernor {
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

    // VULN 1: quorum predicate checks AGAINST votes, not FOR votes.
    function _quorumReached(uint256 proposalId) external view returns (bool) {
        ProposalVote memory v = proposalVotes[proposalId];
        // bug: should be `forVotes + abstainVotes >= quorum()`
        return v.againstVotes >= quorum();
    }

    // VULN 2: _voteSucceeded reads only forVotes without comparing against.
    // A proposal with 1 forVote and 10M againstVotes returns true.
    function _voteSucceeded(uint256 proposalId) external view returns (bool) {
        ProposalVote memory v = proposalVotes[proposalId];
        return v.forVotes >= quorum();
    }

    // VULN 3: state() uses the wrong comparison for "succeeded".
    function state(uint256 proposalId) external view returns (uint256) {
        ProposalVote memory v = proposalVotes[proposalId];
        if (v.againstVotes >= quorum()) return 4; // "Succeeded"
        return 0;
    }
}
