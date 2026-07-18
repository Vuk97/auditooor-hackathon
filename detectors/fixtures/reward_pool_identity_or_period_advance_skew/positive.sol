// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RewardPoolIdentityOrPeriodAdvanceSkewPositive {
    struct PoolKey {
        address token0;
        address token1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }

    mapping(bytes32 => bool) public registeredPools;
    mapping(bytes32 => uint256) public rewardsByPair;

    uint256 public currentPeriod;
    uint256 public totalRaised;
    uint256 public minRaise = 100 ether;

    event AuctionFailed(uint256 period);

    function registerPool(PoolKey calldata key) external {
        bytes32 fullPoolIdentity = keccak256(
            abi.encode(key.token0, key.token1, key.fee, key.tickSpacing, key.hooks)
        );
        registeredPools[fullPoolIdentity] = true;
    }

    function distributeRewards(PoolKey calldata key, uint256 amount) external {
        bytes32 pair = keccak256(abi.encode(key.token0, key.token1));
        rewardsByPair[pair] += amount;
    }

    function claimPoolReward(PoolKey calldata key) external returns (uint256) {
        bytes32 pair = keccak256(abi.encode(key.token0, key.token1));
        uint256 reward = rewardsByPair[pair];
        rewardsByPair[pair] = 0;
        IERC20(key.token0).transfer(msg.sender, reward);
        return reward;
    }

    function closeAuction() external {
        if (totalRaised < minRaise) {
            emit AuctionFailed(currentPeriod);
            totalRaised = 0;
            return;
        }

        currentPeriod++;
        totalRaised = 0;
    }
}
