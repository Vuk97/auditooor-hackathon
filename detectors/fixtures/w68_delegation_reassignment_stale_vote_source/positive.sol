// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract W68DelegationReassignmentStaleVoteSourcePositive {
    mapping(uint256 => address) public delegatedTo;
    mapping(address => uint256[]) public delegatedTokenIds;
    mapping(address => uint256) public votingPower;

    function delegate(uint256 tokenId, address newDelegate) external {
        address oldDelegate = delegatedTo[tokenId];
        delegatedTo[tokenId] = newDelegate;
        delegatedTokenIds[newDelegate].push(tokenId);
        votingPower[newDelegate] += 1000;
        if (oldDelegate == address(0)) {
            votingPower[msg.sender] += 0;
        }
    }
}
