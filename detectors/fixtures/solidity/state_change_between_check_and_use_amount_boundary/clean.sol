// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBoundaryToken {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract AmountBoundaryClean {
    IBoundaryToken public token0;
    IBoundaryToken public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address t0, address t1) {
        token0 = IBoundaryToken(t0);
        token1 = IBoundaryToken(t1);
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        if (amount0Out > 0) {
            token0.transfer(to, amount0Out);
        }
        if (amount1Out > 0) {
            token1.transfer(to, amount1Out);
        }

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));
        uint256 amount0In = balance0 > reserve0 - amount0Out
            ? balance0 - (reserve0 - amount0Out)
            : 0;
        uint256 amount1In = balance1 > reserve1 - amount1Out
            ? balance1 - (reserve1 - amount1Out)
            : 0;

        require(amount0In > 0 || amount1In > 0, "insufficient input");
        uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
        uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
        require(
            balance0Adjusted * balance1Adjusted >= uint256(reserve0) * uint256(reserve1) * 1e6,
            "K"
        );

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
    }
}
