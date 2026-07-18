// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20 { function transferFrom(address from, address to, uint256 amt) external returns (bool); }

contract DrainVuln {
    IERC20 public token;

    function pull(address from, uint256 amount) external {
        token.transferFrom(from, msg.sender, amount);
    }
}
