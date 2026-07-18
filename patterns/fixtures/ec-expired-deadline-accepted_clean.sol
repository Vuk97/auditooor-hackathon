// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: deadline enforced as first check
contract SwapDeadlineClean {
    IERC20 public tokenIn;
    IERC20 public tokenOut;
    uint256 public rate;

    constructor(address _in, address _out, uint256 _rate) {
        tokenIn = IERC20(_in);
        tokenOut = IERC20(_out);
        rate = _rate;
    }

    // CLEAN: deadline check is the first operation
    function swap(uint256 amountIn, uint256 minOut, uint256 deadline) external {
        require(block.timestamp <= deadline, "expired"); // enforced first
        uint256 amountOut = amountIn * rate / 1e18;
        require(amountOut >= minOut, "slippage");
        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(msg.sender, amountOut);
    }
}
