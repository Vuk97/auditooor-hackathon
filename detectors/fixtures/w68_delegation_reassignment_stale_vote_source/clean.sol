// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract W68DelegationReassignmentStaleVoteSourceClean {
    mapping(uint256 => address) public delegatedTo;
    mapping(address => uint256[]) public delegatedTokenIds;
    mapping(address => uint256) public votingPower;

    function delegate(uint256 tokenId, address newDelegate) external {
        address oldDelegate = delegatedTo[tokenId];
        if (oldDelegate != address(0)) {
            _removeDelegation(oldDelegate, tokenId);
            votingPower[oldDelegate] -= 1000;
        }
        delegatedTo[tokenId] = newDelegate;
        delegatedTokenIds[newDelegate].push(tokenId);
        votingPower[newDelegate] += 1000;
    }

    function _removeDelegation(address oldDelegate, uint256 tokenId) internal {
        uint256[] storage entries = delegatedTokenIds[oldDelegate];
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i] == tokenId) {
                entries[i] = entries[entries.length - 1];
                entries.pop();
                break;
            }
        }
    }
}
