// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoterPokeClean {
    address public votingEscrow;
    mapping(address => uint256) public snapshot;
    mapping(address => uint256) public rewardPerVote;
    function poke(address user) external {
        require(msg.sender == user || msg.sender == votingEscrow, "not authorized");
        snapshot[user] = block.number;
        rewardPerVote[user] = 0;
    }
}
