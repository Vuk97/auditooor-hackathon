// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// block-number-time-assumption detector. DO NOT DEPLOY.
///
/// Converts `block.number` to seconds using a hard-coded 12s-per-block
/// multiplier. Correct on Ethereum mainnet; wrong by an integer multiple
/// on Arbitrum (~0.25s), Optimism / Base / Polygon (~2s), BSC (~3s).
contract StakingEmissionsVuln {
    uint256 public startBlock;
    uint256 public rewardPerSecond;
    uint256 public constant blocksPerDay = 7200; // implies 12s blocks

    constructor(uint256 _rewardPerSecond) {
        startBlock = block.number;
        rewardPerSecond = _rewardPerSecond;
    }

    // VULN (shape A): `block.number * 12` as elapsed-seconds estimate.
    function secondsElapsedA() external view returns (uint256) {
        return block.number * 12;
    }

    // VULN (shape B): `(block.number - startBlock) * 12` — the canonical
    // staking-schedule shape. On Arbitrum this is 48x too small.
    function rewardsAccrued() external view returns (uint256) {
        uint256 elapsedSeconds = (block.number - startBlock) * 12;
        return elapsedSeconds * rewardPerSecond;
    }
}
