// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBoundaryToken {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract AmountBoundaryVulnerable {
    IBoundaryToken public token0;
    IBoundaryToken public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address t0, address t1) {
        token0 = IBoundaryToken(t0);
        token1 = IBoundaryToken(t1);
    }

    function swap(uint256 amount0In, uint256 amount1Out, address to) external {
        require(amount0In > 0 && amount1Out > 0, "bad swap");

        uint256 amountOutQuoted = amount0In * uint256(reserve1) / uint256(reserve0);
        token1.transfer(to, amount1Out);

        uint256 newBal0 = token0.balanceOf(address(this));
        uint256 newBal1 = token1.balanceOf(address(this));
        require(newBal0 * newBal1 >= uint256(reserve0) * uint256(reserve1), "K");

        reserve0 = uint112(newBal0);
        reserve1 = uint112(newBal1);
        amountOutQuoted;
    }
}
