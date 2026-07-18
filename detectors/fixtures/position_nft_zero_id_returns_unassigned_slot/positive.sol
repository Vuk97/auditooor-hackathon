// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PositionNftZeroIdPositive {
    error NotKeyOwner();

    mapping(address => uint256) public reservedKeys;
    mapping(uint256 => uint256) public availableNFTs;
    mapping(uint256 => address) public claimedBy;

    function seed(address user, uint256 keyId, uint256 nftId) external {
        reservedKeys[user] = keyId;
        availableNFTs[keyId] = nftId;
    }

    function exitFarm(uint256 keyId) external returns (uint256 nftId) {
        if (reservedKeys[msg.sender] == keyId) {
            reservedKeys[msg.sender] = 0;
        } else {
            revert NotKeyOwner();
        }

        nftId = availableNFTs[keyId];
        claimedBy[nftId] = msg.sender;
    }
}
