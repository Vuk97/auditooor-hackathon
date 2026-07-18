// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISubscriber {
    function notifySubscribe(uint256 tokenId, address owner, bytes calldata data) external;
    function notifyUnsubscribe(uint256 tokenId, address owner, bytes calldata data) external;
}

contract RewardTracker is ISubscriber {
    mapping(uint256 => address) public positionOwner;
    mapping(address => uint256) public rewardDebt;

    function notifySubscribe(uint256 tokenId, address owner, bytes calldata) external {
        positionOwner[tokenId] = owner;
        rewardDebt[owner] = block.timestamp;
    }

    function notifyUnsubscribe(uint256 tokenId, address owner, bytes calldata) external {
        delete positionOwner[tokenId];
        delete rewardDebt[owner];
    }

    function notifyBurn(uint256 tokenId, bytes calldata) external {
        delete positionOwner[tokenId];
    }

    function notifyModifyLiquidity(uint256 tokenId, bytes calldata) external {
        rewardDebt[positionOwner[tokenId]] = block.timestamp;
    }

    function accrueRewards(uint256 tokenId) external view returns (uint256) {
        address owner = positionOwner[tokenId];
        return (block.timestamp - rewardDebt[owner]) * 1e18 / 86400;
    }
}