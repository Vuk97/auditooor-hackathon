// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VotePowerReassignmentMissingDebitClean {
    mapping(address => uint256) public deposits;
    mapping(address => address) public voteSourceOf;
    mapping(address => uint256) public votePowerBySource;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => uint256) public forVotes;

    function seed(address voter, uint256 amount) external {
        deposits[voter] = amount;
    }

    function reassignVoteSource(address voter, address newSource) external {
        address oldSource = voteSourceOf[voter];
        uint256 amount = deposits[voter];

        if (oldSource == newSource) {
            return;
        }
        if (oldSource != address(0)) {
            votePowerBySource[oldSource] -= amount;
        }

        voteSourceOf[voter] = newSource;
        votePowerBySource[newSource] += amount;
    }

    function castVote(uint256 proposalId) external {
        require(!hasVoted[proposalId][msg.sender], "already voted");
        hasVoted[proposalId][msg.sender] = true;
        forVotes[proposalId] += votePowerBySource[msg.sender];
    }
}
