// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteSourceArrayReassignmentPositive {
    mapping(uint256 => address) public delegateOfSource;
    mapping(address => uint256[]) public delegateSources;
    mapping(uint256 => uint256) public sourceVotingPower;

    function changeDelegate(uint256 sourceId, address newDelegate) external {
        address currentDelegate = delegateOfSource[sourceId];
        delegateOfSource[sourceId] = newDelegate;
        delegateSources[newDelegate].push(sourceId);
        currentDelegate;
    }

    function votingPowerOf(address delegatee) external view returns (uint256 total) {
        uint256[] storage sources = delegateSources[delegatee];
        for (uint256 i = 0; i < sources.length; i++) {
            total += sourceVotingPower[sources[i]];
        }
    }
}

contract VotePowerLedgerReassignmentPositive {
    mapping(address => address) public delegateOf;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegateVotePower;

    function seed(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }

    function setDelegate(address to) external {
        address previousDelegate = delegateOf[msg.sender];
        delegateOf[msg.sender] = to;
        delegateVotePower[to] += balanceOf[msg.sender];
        previousDelegate;
    }
}
