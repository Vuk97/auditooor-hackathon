// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract W68VoteDoubleCountDelegationClean {
    mapping(address => uint256) private _votingPower;
    mapping(uint256 => uint256) public proposalVotes;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    constructor() {
        _votingPower[msg.sender] = 100 ether;
    }

    function balanceOf(address voter) public view returns (uint256) {
        return _votingPower[voter];
    }

    function castVote(uint256 proposalId) external {
        require(!hasVoted[proposalId][msg.sender], "already voted");
        hasVoted[proposalId][msg.sender] = true;
        proposalVotes[proposalId] += balanceOf(msg.sender);
    }
}
