// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ADepositorOfTheGmxvaultCanBypassPayingTheFeeWhenTheD {
    uint256 internal depositAmount;

    function deposit(uint256 amount) external {
        _accrue();
        bool feeApplied = mintFee();
        depositAmount += amount;
    }

    function _accrue() internal {
        // fee accrual logic
    }

    function mintFee() internal view returns (bool) {
        return depositAmount > 0;
    }
}
