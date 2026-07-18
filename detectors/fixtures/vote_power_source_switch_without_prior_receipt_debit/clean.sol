// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VotePowerSourceSwitchWithoutPriorReceiptDebitClean {
    mapping(address => uint256) private _balances;
    mapping(address => address) public delegates;
    mapping(address => mapping(uint256 => uint256)) public voteCheckpoints;
    mapping(uint256 => uint256) public proposalSnapshot;
    mapping(uint256 => uint256) public forVotes;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    constructor() {
        _balances[msg.sender] = 100 ether;
        voteCheckpoints[msg.sender][1] = 100 ether;
        proposalSnapshot[7] = 1;
    }

    function delegate(address delegatee) external {
        require(delegatee != msg.sender, "self delegation disabled");
        delegates[msg.sender] = delegatee;
    }

    function castVote(uint256 proposalId) external {
        address voter = msg.sender;
        require(!hasVoted[proposalId][voter], "already voted");
        hasVoted[proposalId][voter] = true;
        uint256 snapshot = proposalSnapshot[proposalId];
        uint256 weight = voteCheckpoints[voter][snapshot];
        forVotes[proposalId] += weight;
    }
}
