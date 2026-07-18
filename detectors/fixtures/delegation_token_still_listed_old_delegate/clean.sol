// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationTokenStillListedOldDelegateClean {
    mapping(uint256 => uint256) public delegatedTo;
    mapping(uint256 => uint256[]) public tokensByDelegate;

    function delegate(uint256 tokenId, uint256 newDelegate) external {
        uint256 oldDelegate = delegatedTo[tokenId];
        if (oldDelegate != 0) {
            _removeTokenFromDelegate(oldDelegate, tokenId);
        }

        delegatedTo[tokenId] = newDelegate;
        tokensByDelegate[newDelegate].push(tokenId);
    }

    function _removeTokenFromDelegate(uint256 oldDelegate, uint256 tokenId) internal {
        uint256[] storage tokenIds = tokensByDelegate[oldDelegate];
        for (uint256 i = 0; i < tokenIds.length; i++) {
            if (tokenIds[i] == tokenId) {
                tokenIds[i] = tokenIds[tokenIds.length - 1];
                tokenIds.pop();
                return;
            }
        }
    }
}
