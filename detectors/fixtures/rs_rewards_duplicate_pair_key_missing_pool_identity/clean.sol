// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RsRewardsDuplicatePairKeyMissingPoolIdentityClean {
    struct PoolKey {
        address token0;
        address token1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }

    mapping(bytes32 => bytes32) public canonicalPoolForPair;
    mapping(bytes32 => uint256) public rewardsByPool;

    function registerPool(PoolKey calldata key) external {
        bytes32 pair = pairKey(key);
        bytes32 poolId = poolKey(key);
        require(canonicalPoolForPair[pair] == bytes32(0), "duplicate pair");
        canonicalPoolForPair[pair] = poolId;
    }

    function distributeRewards(PoolKey calldata key, uint256 amount) external {
        bytes32 pair = pairKey(key);
        bytes32 poolId = poolKey(key);
        require(canonicalPoolForPair[pair] == poolId, "not canonical");
        rewardsByPool[poolId] += amount;
    }

    function claimRewards(PoolKey calldata key) external returns (uint256) {
        bytes32 pair = pairKey(key);
        bytes32 poolId = poolKey(key);
        require(canonicalPoolForPair[pair] == poolId, "not canonical");
        uint256 reward = rewardsByPool[poolId];
        rewardsByPool[poolId] = 0;
        IERC20(key.token0).transfer(msg.sender, reward);
        return reward;
    }

    function pairKey(PoolKey calldata key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key.token0, key.token1));
    }

    function poolKey(PoolKey calldata key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key.token0, key.token1, key.fee, key.tickSpacing, key.hooks));
    }
}
