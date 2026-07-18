// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationTokenStillListedOldDelegatePositive {
    mapping(uint256 => uint256) public delegatedTo;
    mapping(uint256 => uint256[]) public tokensByDelegate;

    function delegate(uint256 tokenId, uint256 newDelegate) external {
        uint256 oldDelegate = delegatedTo[tokenId];

        delegatedTo[tokenId] = newDelegate;
        tokensByDelegate[newDelegate].push(tokenId);

        oldDelegate;
    }
}
