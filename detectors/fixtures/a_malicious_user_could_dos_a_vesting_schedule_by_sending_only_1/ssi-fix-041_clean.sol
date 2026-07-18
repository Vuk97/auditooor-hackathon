// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VestingScheduleDustDosClean {
    uint256 internal balanceOfEscrow;
    uint256 internal lastReleasableAmount;

    function dustVestingEscrow() external payable {
        balanceOfEscrow += msg.value;
    }

    function computeVestingReleasableAmount() external returns (uint256) {
        _accrueEscrowDust();
        uint256 escrowBalance = balanceOfEscrow;
        if (escrowBalance > 0) {
            lastReleasableAmount = escrowBalance;
        }
        return lastReleasableAmount;
    }

    function _accrueEscrowDust() internal {
        if (balanceOfEscrow == 0) {
            balanceOfEscrow = 1;
        }
    }
}
