// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same staking-emissions
/// shape as the vuln fixture, but uses `block.timestamp` for wall-clock
/// measurement instead of converting block heights with a hard-coded
/// seconds-per-block constant.
contract StakingEmissionsClean {
    uint256 public startTimestamp;
    uint256 public rewardPerSecond;

    constructor(uint256 _rewardPerSecond) {
        startTimestamp = block.timestamp;
        rewardPerSecond = _rewardPerSecond;
    }

    // CLEAN: use block.timestamp directly — portable across every EVM chain.
    function secondsElapsed() external view returns (uint256) {
        return block.timestamp - startTimestamp;
    }

    // CLEAN: rewards accrue off wall-clock time, not block count.
    function rewardsAccrued() external view returns (uint256) {
        uint256 elapsedSeconds = block.timestamp - startTimestamp;
        return elapsedSeconds * rewardPerSecond;
    }
}
