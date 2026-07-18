// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: weight uses a single snapshotted voting-power source.
contract VoteDoubleCountSafe {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => uint256) public proposalVotes;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    function castVote(uint256 proposalId) external {
        require(!hasVoted[proposalId][msg.sender], "already voted");
        hasVoted[proposalId][msg.sender] = true;
        proposalVotes[proposalId] += votingPower[msg.sender];
    }
}
