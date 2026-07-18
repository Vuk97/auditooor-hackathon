// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract W68VoteDoubleCountDelegationPositive {
    mapping(address => uint256) private _balances;
    mapping(address => uint256) public delegatedPower;
    mapping(uint256 => uint256) public proposalVotes;

    constructor() {
        _balances[msg.sender] = 100 ether;
        delegatedPower[msg.sender] = 100 ether;
    }

    function balanceOf(address voter) public view returns (uint256) {
        return _balances[voter];
    }

    function castVote(uint256 proposalId) external {
        uint256 weight = balanceOf(msg.sender) + delegatedPower[msg.sender];
        proposalVotes[proposalId] += weight;
    }
}
