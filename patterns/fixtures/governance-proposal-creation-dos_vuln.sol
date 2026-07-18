// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: governance propose/cancel paths are all griefable.
// - propose: caller-supplied id, no dedup, attacker front-runs to squat id.
// - cancelProposal: strict equality lets anyone cancel at exactly-threshold.
// - submitProposal: threshold >= check against attacker-inflatable counter.
contract GovernanceDosVuln {
    struct Proposal {
        address proposer;
        uint256 votes;
        bool exists;
    }

    mapping(bytes32 => Proposal) public proposals;
    uint256 public proposalThreshold;
    uint256 public quorum;

    // VULN 1: caller supplies proposalId, no dedup.
    function propose(bytes32 proposalId, uint256 votes) external {
        // no require(!proposals[proposalId].exists) — attacker squats ids.
        proposals[proposalId] = Proposal(msg.sender, votes, true);
    }

    // VULN 2: createProposal relies on proposalThreshold >=, inflatable.
    function createProposal(bytes32 proposalId) external {
        require(proposals[proposalId].votes >= proposalThreshold, "below");
        proposals[proposalId].exists = true;
    }

    // VULN 3: strict-equality cancel — anyone can cancel at threshold.
    function cancelProposal(bytes32 proposalId) external {
        require(proposals[proposalId].votes == proposalThreshold, "mismatch");
        delete proposals[proposalId];
    }

    // VULN 4: submitProposal with threshold >= gate, no dedup.
    function submitProposal(bytes32 proposalId) external {
        require(proposals[proposalId].votes >= proposalThreshold, "votes");
        proposals[proposalId].proposer = msg.sender;
    }
}
