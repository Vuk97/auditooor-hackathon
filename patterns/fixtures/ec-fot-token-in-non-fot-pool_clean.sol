// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: uses balance delta (not parameter) for amountIn calculation
// Uniswap V2 canonical approach: delta = newBalance - reserve
contract AMMClean {
    IERC20 public token0;
    IERC20 public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address _t0, address _t1) { token0 = IERC20(_t0); token1 = IERC20(_t1); }

    // CLEAN: amountIn computed as balance delta — FoT tokens handled correctly
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        if (amount0Out > 0) token0.transfer(to, amount0Out);
        if (amount1Out > 0) token1.transfer(to, amount1Out);

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        // amountIn is the ACTUAL received delta — works correctly for FoT
        uint256 amount0In = balance0 > reserve0 - amount0Out ? balance0 - (reserve0 - amount0Out) : 0;
        uint256 amount1In = balance1 > reserve1 - amount1Out ? balance1 - (reserve1 - amount1Out) : 0;

        require(amount0In > 0 || amount1In > 0, "insufficient input");
        uint256 bal0Adj = balance0 * 1000 - amount0In * 3;
        uint256 bal1Adj = balance1 * 1000 - amount1In * 3;
        require(bal0Adj * bal1Adj >= uint256(reserve0) * reserve1 * 1e6, "K");
        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
    }
}
