// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteDoubleCountStaleSourceRetentionPositive {
    mapping(uint256 => address) public delegateOf;
    mapping(address => uint256[]) public delegatedSources;
    mapping(uint256 => uint256) public votingPower;
    mapping(uint256 => uint256) public forVotes;

    function reassignAndRevote(uint256 proposalId, uint256 sourceId, address newDelegate) external {
        address oldDelegate = delegateOf[sourceId];
        delegateOf[sourceId] = newDelegate;

        delegatedSources[newDelegate].push(sourceId);
        uint256 weight = votingPower[sourceId];
        forVotes[proposalId] += weight;

        oldDelegate;
    }
}
