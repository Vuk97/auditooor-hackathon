// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

// VULN: AMM k-check based on balance delta but output computed from amountIn param
// Loss ref: PancakeSwap V2 fork FoT bypass, BSC 2021; OpenLeverage2 April 2024
// https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/OpenLeverage2_exp.sol
contract AMMVuln {
    IERC20 public token0;
    IERC20 public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address _t0, address _t1) { token0 = IERC20(_t0); token1 = IERC20(_t1); }

    // VULN: uses amount0In parameter for amountOut, but k-check uses actual balance
    // FoT token: actual received < amount0In → amountOut inflated relative to real input
    function swap(uint256 amount0In, uint256 amount0Out, uint256 amount1Out, address to) external {
        require(amount0Out > 0 || amount1Out > 0, "insufficient output");
        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));
        // amountOut computed from PARAMETER (not balance delta) — FoT mismatch
        uint256 amountOut1 = amount0In * reserve1 / reserve0; // uses nominal amountIn
        if (amount1Out > 0) token1.transfer(to, amount1Out);
        uint256 newBal0 = token0.balanceOf(address(this));
        uint256 newBal1 = token1.balanceOf(address(this));
        require(newBal0 * newBal1 >= uint256(reserve0) * uint256(reserve1), "K");
        reserve0 = uint112(newBal0);
        reserve1 = uint112(newBal1);
        (balance0, balance1, amountOut1); // suppress warnings
    }
}
