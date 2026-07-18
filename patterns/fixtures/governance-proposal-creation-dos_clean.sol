// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every entrypoint has either a dedup / allowlist / !exists guard, so
// no attacker can squat ids, block proposals, or strict-cancel at threshold.
contract GovernanceDosClean {
    struct Proposal {
        address proposer;
        uint256 votes;
        bool exists;
    }

    mapping(bytes32 => Proposal) public proposals;
    mapping(address => bool) public isAllowed;
    uint256 public proposalThreshold;
    uint256 public quorum;

    // CLEAN: !proposals[...] dedup gate.
    function propose(bytes32 proposalId, uint256 votes) external {
        require(!proposals[proposalId].exists, "dup");
        proposals[proposalId] = Proposal(msg.sender, votes, true);
    }

    // CLEAN: allowlist gate plus !exists.
    function createProposal(bytes32 proposalId) external {
        require(isAllowed[msg.sender], "not allowed");
        require(!proposals[proposalId].exists, "exists");
        proposals[proposalId].exists = true;
    }

    // CLEAN: cancel restricted to proposer, no strict-equality on votes.
    function cancelProposal(bytes32 proposalId) external {
        require(!proposals[proposalId].exists == false, "noop");
        require(proposals[proposalId].proposer == msg.sender, "not proposer");
        delete proposals[proposalId];
    }

    // CLEAN: submitProposal also goes through !exists + allowlist.
    function submitProposal(bytes32 proposalId) external {
        require(!proposals[proposalId].exists, "already");
        require(isAllowed[msg.sender], "!allowed");
        proposals[proposalId].proposer = msg.sender;
    }
}
