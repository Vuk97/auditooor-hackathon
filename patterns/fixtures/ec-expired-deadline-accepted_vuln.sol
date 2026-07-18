// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// VULN: deadline parameter accepted but never checked against block.timestamp
// Loss ref: Uniswap V3 expired-deadline pattern, 2022-2024
// SWC-116: https://swcregistry.io/docs/SWC-116
contract SwapDeadlineVuln {
    IERC20 public tokenIn;
    IERC20 public tokenOut;
    uint256 public rate; // simple rate for demo

    constructor(address _in, address _out, uint256 _rate) {
        tokenIn = IERC20(_in);
        tokenOut = IERC20(_out);
        rate = _rate;
    }

    // VULN: deadline parameter exists but is never enforced
    function swap(uint256 amountIn, uint256 minOut, uint256 deadline) external {
        // MISSING: require(block.timestamp <= deadline, "expired")
        uint256 amountOut = amountIn * rate / 1e18;
        require(amountOut >= minOut, "slippage");
        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(msg.sender, amountOut);
        // expired-deadline tx can be held and executed when rate diverges
    }
}
