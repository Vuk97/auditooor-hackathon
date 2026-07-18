// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VotingPowerSelfDelegationDoubleCountPositive {
    mapping(address => uint256) private _balances;
    mapping(address => address) public delegates;
    mapping(address => mapping(uint256 => uint256)) public voteCheckpoints;
    mapping(uint256 => uint256) public proposalSnapshot;
    mapping(uint256 => uint256) public forVotes;

    constructor() {
        _balances[msg.sender] = 100 ether;
        delegates[msg.sender] = msg.sender;
        voteCheckpoints[msg.sender][1] = 100 ether;
        proposalSnapshot[7] = 1;
    }

    function delegate(address delegatee) external {
        delegates[msg.sender] = delegatee;
    }

    function castBallot(uint256 proposalId) external {
        address voter = msg.sender;
        uint256 snapshot = proposalSnapshot[proposalId];
        uint256 weight = _balances[voter] + voteCheckpoints[delegates[voter]][snapshot];
        forVotes[proposalId] += weight;
    }
}
