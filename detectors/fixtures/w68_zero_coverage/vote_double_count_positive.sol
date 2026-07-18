// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: castVote tallies both the caller's own balance and any
// delegated power, double-counting self-delegated weight.
contract VoteDoubleCountVulnerable {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegatedTo;
    mapping(uint256 => uint256) public proposalVotes;

    function castVote(uint256 proposalId) external {
        uint256 weight = balanceOf[msg.sender] + delegatedTo[msg.sender];
        proposalVotes[proposalId] += weight;
    }
}
