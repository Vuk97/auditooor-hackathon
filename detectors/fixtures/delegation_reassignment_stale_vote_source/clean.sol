// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationReassignmentStaleVoteSourceClean {
    mapping(uint256 => uint256) public delegatedTo;
    mapping(uint256 => uint256[]) public delegatedTokenIds;

    function delegate(uint256 tokenId, uint256 toTokenId) external {
        uint256 oldDelegate = delegatedTo[tokenId];
        if (oldDelegate != 0) {
            _removeDelegation(oldDelegate, tokenId);
        }
        delegatedTo[tokenId] = toTokenId;
        delegatedTokenIds[toTokenId].push(tokenId);
    }

    function _removeDelegation(uint256 oldDelegate, uint256 tokenId) internal {
        uint256[] storage ids = delegatedTokenIds[oldDelegate];
        for (uint256 i = 0; i < ids.length; i++) {
            if (ids[i] == tokenId) {
                ids[i] = ids[ids.length - 1];
                ids.pop();
                return;
            }
        }
    }
}
