// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovValidatorVotingPowerPositive {
    mapping(address => uint256) internal votePower;
    mapping(address => uint256) internal lastVoteByValidator;
    mapping(uint256 => uint256) internal proposalApprovals;

    constructor() {
        votePower[msg.sender] = 1;
    }

    function vote(uint256 proposalId) external returns (bool) {
        uint256 currentVotePower = votePower[msg.sender];
        require(currentVotePower > 0, "validator lost power");

        lastVoteByValidator[msg.sender] = proposalId;
        proposalApprovals[proposalId] += currentVotePower;
        return true;
    }
}
