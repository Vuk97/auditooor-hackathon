// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BidirectionalSwapPositive {
    uint256 public reserve0 = 1_000_000 ether;
    uint256 public reserve1 = 1_000_000 ether;
    uint256 public feeGrowth0;
    uint256 public feeGrowth1;

    function swap(bool zeroForOne, uint256 amountIn) external returns (uint256 amountOut) {
        require(amountIn > 0, "amount");

        if (zeroForOne) {
            uint256 fee = amountIn / 300;
            uint256 amountAfterFee = amountIn - fee;
            amountOut = (amountAfterFee * reserve1) / (reserve0 + amountAfterFee);

            reserve0 += amountIn;
            reserve1 -= amountOut;
            feeGrowth0 += fee;
        } else {
            amountOut = (amountIn * reserve0) / (reserve1 + amountIn);
            uint256 fee = amountOut / 300;

            reserve1 += amountIn;
            reserve0 -= amountOut;
            feeGrowth1 += fee;
        }
    }
}
