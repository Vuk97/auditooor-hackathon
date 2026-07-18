// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStakingRewardsZeroVaultPositive {
    struct PoolInfo {
        address stakingToken;
    }

    function getPool(uint256 poolId) external view returns (PoolInfo memory);
}

contract MissingZeroCheckOnVaultAddressDepositAndStakePositive {
    address public stakingRewards;

    constructor(address rewards) {
        stakingRewards = rewards;
    }

    function depositAndStake(
        address vaultAddress,
        uint256 poolId,
        uint256 amount0Desired,
        uint256 amount1Desired
    ) external {
        require(
            IStakingRewardsZeroVaultPositive(stakingRewards).getPool(poolId).stakingToken == vaultAddress,
            "Incorrect pool id"
        );
        _deposit(vaultAddress, amount0Desired, amount1Desired);
    }

    function _deposit(address vaultAddress, uint256 amount0Desired, uint256 amount1Desired) internal pure {
        vaultAddress;
        amount0Desired;
        amount1Desired;
    }
}
