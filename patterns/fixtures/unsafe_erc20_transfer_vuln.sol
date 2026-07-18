// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract UnsafeERC20Vuln {
    IERC20 public immutable token;
    constructor(address t) { token = IERC20(t); }

    function sendTokens(address to, uint256 amt) external {
        token.transfer(to, amt);  // unchecked, breaks on USDT-like
    }

    function pullTokens(address from, uint256 amt) external {
        token.transferFrom(from, address(this), amt);
    }
}
