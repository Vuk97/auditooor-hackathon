// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeAccrualMissingVuln {
    uint256 public feePerSecond;
    uint256 public lastFeeCollected;
    uint256 public accumulatedFees;

    // Accrual helper exists (satisfies contract-level precondition).
    function accrueFee() public {
        uint256 dt = block.timestamp - lastFeeCollected;
        accumulatedFees += feePerSecond * dt;
        lastFeeCollected = block.timestamp;
    }

    // VULN: changes feePerSecond without calling accrueFee first. Any fees
    // that built up under the old rate are silently re-priced at the new one.
    function setFeePerSecond(uint256 newRate) external {
        feePerSecond = newRate;
    }

    // VULN: charges fees without running accrual first.
    function chargeFee(address /*user*/, uint256 amt) external {
        accumulatedFees += amt;
    }
}
