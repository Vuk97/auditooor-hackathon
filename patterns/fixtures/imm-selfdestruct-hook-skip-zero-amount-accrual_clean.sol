// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccrualHookClean {
    uint256 public lastIndex;
    uint256 public currentIndex;
    mapping(address => uint256) public accrued;

    function _settleAccrual(address who, uint256 amount) internal {
        accrued[who] += amount;
    }

    // FIXED: lastIndex bookmark updates UNCONDITIONALLY — even when the
    // amount being settled is zero.
    function onDestroy(address contractAddr, address tokenReceiver) external {
        uint256 amount = (currentIndex - lastIndex);
        if (amount != 0) {
            _settleAccrual(tokenReceiver, amount);
        }
        lastIndex = currentIndex; // always advances the emission clock
        contractAddr; // silence
    }
}
