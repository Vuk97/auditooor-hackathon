// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISubscriber {
    function notifySubscribe(uint256 tokenId, address owner, bytes calldata data) external;
    function notifyUnsubscribe(uint256 tokenId, address owner, bytes calldata data) external;
}

contract RewardTracker is ISubscriber {
    address public immutable positionManager;

    mapping(uint256 => address) public positionOwner;
    mapping(address => uint256) public rewardDebt;

    modifier onlyByPosm() {
        require(msg.sender == positionManager, "not posm");
        _;
    }

    constructor(address _positionManager) {
        positionManager = _positionManager;
    }

    function notifySubscribe(uint256 tokenId, address owner, bytes calldata) external onlyByPosm {
        positionOwner[tokenId] = owner;
        rewardDebt[owner] = block.timestamp;
    }

    function notifyUnsubscribe(uint256 tokenId, address owner, bytes calldata) external onlyByPosm {
        delete positionOwner[tokenId];
        delete rewardDebt[owner];
    }

    function notifyBurn(uint256 tokenId, bytes calldata) external onlyByPosm {
        delete positionOwner[tokenId];
    }

    function notifyModifyLiquidity(uint256 tokenId, bytes calldata) external onlyByPosm {
        rewardDebt[positionOwner[tokenId]] = block.timestamp;
    }

    function accrueRewards(uint256 tokenId) external view returns (uint256) {
        address owner = positionOwner[tokenId];
        return (block.timestamp - rewardDebt[owner]) * 1e18 / 86400;
    }
}