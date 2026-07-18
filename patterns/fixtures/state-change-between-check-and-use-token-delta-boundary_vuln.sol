// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Boundary {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TokenDeltaBoundaryVuln {
    IERC20Boundary public token0;
    IERC20Boundary public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address _token0, address _token1) {
        token0 = IERC20Boundary(_token0);
        token1 = IERC20Boundary(_token1);
    }

    function swap(uint256 amount0In, uint256 amount1Out, address to) external {
        require(amount1Out > 0, "no output");

        uint256 quotedOut = amount0In * uint256(reserve1) / uint256(reserve0);
        token1.transfer(to, amount1Out);

        uint256 newBal0 = token0.balanceOf(address(this));
        uint256 newBal1 = token1.balanceOf(address(this));
        require(newBal0 * newBal1 >= uint256(reserve0) * uint256(reserve1), "K");

        reserve0 = uint112(newBal0);
        reserve1 = uint112(newBal1);
        quotedOut;
    }
}
