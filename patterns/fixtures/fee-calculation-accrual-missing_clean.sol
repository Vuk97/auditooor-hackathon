// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeAccrualMissingClean {
    uint256 public feePerSecond;
    uint256 public lastFeeCollected;
    uint256 public accumulatedFees;

    function accrueFee() public {
        uint256 dt = block.timestamp - lastFeeCollected;
        accumulatedFees += feePerSecond * dt;
        lastFeeCollected = block.timestamp;
    }

    // CLEAN: materializes pending fees under the old rate before updating.
    function setFeePerSecond(uint256 newRate) external {
        accrueFee();
        feePerSecond = newRate;
    }

    // CLEAN: runs accrual before levying new fees.
    function chargeFee(address /*user*/, uint256 amt) external {
        accrueFee();
        accumulatedFees += amt;
    }
}
