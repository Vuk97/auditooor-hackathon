// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationReassignmentStaleVoteSourcePositive {
    mapping(uint256 => uint256) public delegatedTo;
    mapping(uint256 => uint256[]) public delegatedTokenIds;

    function delegate(uint256 tokenId, uint256 toTokenId) external {
        uint256 oldDelegate = delegatedTo[tokenId];
        delegatedTo[tokenId] = toTokenId;
        delegatedTokenIds[toTokenId].push(tokenId);
        oldDelegate;
    }
}
