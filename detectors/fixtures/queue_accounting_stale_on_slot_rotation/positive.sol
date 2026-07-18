// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WithdrawalQueueSlotRotationPositive {
    struct QueueAccounting {
        uint256 shareFraction;
        uint256 totalShares;
    }

    mapping(uint256 => uint256) internal _queueOutstandingValues;
    mapping(uint256 => QueueAccounting) internal _queueAccounting;
    uint256 public lastQueueIndex;
    uint256 internal constant QUEUE_SLOTS = 2;

    constructor() {
        _queueAccounting[0].shareFraction = 25e16;
        _queueOutstandingValues[0] = 10 ether;
    }

    function deployWithdrawalQueue() external {
        uint256 nextQueueIndex = (lastQueueIndex + 1) % QUEUE_SLOTS;
        delete _queueOutstandingValues[lastQueueIndex];
        _queueAccounting[nextQueueIndex].shareFraction = 1e18;
        _queueAccounting[nextQueueIndex].totalShares = 1;
        lastQueueIndex = nextQueueIndex;
    }

    function queueClaimAll(uint256 queueIndex, uint256 received) external view returns (uint256) {
        return (received * _queueAccounting[queueIndex].shareFraction) / 1e18;
    }
}
