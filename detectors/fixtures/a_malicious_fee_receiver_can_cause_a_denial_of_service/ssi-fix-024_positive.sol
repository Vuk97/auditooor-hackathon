// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFeeReceiver {
    function receiveFee(uint256 amount) external;
}

contract MaliciousFeeReceiver {
    function receiveFee(uint256) external pure {
        revert("deny");
    }
}

contract FeeDistributorDoSPositive {
    address[] internal feeReceivers;
    uint256 internal accruedFees;

    constructor(address[] memory initialReceivers) {
        feeReceivers = initialReceivers;
    }

    function setAccruedFees(uint256 newAccruedFees) external {
        accruedFees = newAccruedFees;
    }

    function distributeFees() external {
        uint256 amountPerReceiver = accruedFees / feeReceivers.length;
        for (uint256 i = 0; i < feeReceivers.length; ++i) {
            IFeeReceiver(feeReceivers[i]).receiveFee(amountPerReceiver);
        }
    }
}
