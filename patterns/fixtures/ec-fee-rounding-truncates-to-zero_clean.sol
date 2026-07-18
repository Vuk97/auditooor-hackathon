// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: minimum amount enforced OR minimum fee floor applied
contract FeeClean {
    uint256 public constant FEE_BPS = 30;
    uint256 public constant MIN_AMOUNT = 334; // below this, fee would be 0
    uint256 public collectedFees;

    // CLEAN: rejects dust amounts that would bypass fee
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        require(amountIn >= MIN_AMOUNT, "amount below minimum");
        uint256 fee = amountIn * FEE_BPS / 10000;
        require(fee >= 1, "fee rounds to zero"); // belt-and-suspenders
        collectedFees += fee;
        amountOut = amountIn - fee;
    }
}
