// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VotePowerSelfDelegationDoubleCount {
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegateOf;
    mapping(address => uint256) public delegatedVotes;
    mapping(address => bool) public selfDelegated;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => uint256) public forVotes;

    function seed(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }

    function selfDelegate() external {
        require(delegateOf[msg.sender] == address(0), "already delegated");
        delegateOf[msg.sender] = msg.sender;
        selfDelegated[msg.sender] = true;
        delegatedVotes[msg.sender] += balanceOf[msg.sender];
    }

    function delegate(address newDelegate) external {
        require(newDelegate != address(0), "zero delegate");
        address oldDelegate = delegateOf[msg.sender];

        delegateOf[msg.sender] = newDelegate;
        selfDelegated[msg.sender] = newDelegate == msg.sender;
        delegatedVotes[newDelegate] += balanceOf[msg.sender];

        oldDelegate;
    }

    function castVote(uint256 proposalId) external {
        require(!hasVoted[proposalId][msg.sender], "already voted");
        hasVoted[proposalId][msg.sender] = true;
        forVotes[proposalId] += delegatedVotes[msg.sender];
    }
}
