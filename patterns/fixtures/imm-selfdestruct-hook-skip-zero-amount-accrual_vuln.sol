// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccrualHookVuln {
    uint256 public lastIndex;
    uint256 public currentIndex;
    mapping(address => uint256) public accrued;

    function _settleAccrual(address who, uint256 amount) internal {
        accrued[who] += amount;
    }

    // VULN: onDestroy updates accrual and lastIndex only when amount != 0.
    // If amount == 0 the index bookmark is never updated.
    function onDestroy(address contractAddr, address tokenReceiver) external {
        uint256 amount = (currentIndex - lastIndex);
        if (amount != 0) {
            _settleAccrual(tokenReceiver, amount);
            lastIndex = currentIndex; // only in this branch
        }
        contractAddr; // silence
    }
}
