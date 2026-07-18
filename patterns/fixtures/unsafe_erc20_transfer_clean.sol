// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

// Minimal SafeERC20
library SafeERC20 {
    function safeTransfer(IERC20 t, address to, uint256 amt) internal {
        bool ok = t.transfer(to, amt);
        require(ok, "safeTransfer failed");
    }

    function safeTransferFrom(IERC20 t, address from, address to, uint256 amt) internal {
        bool ok = t.transferFrom(from, to, amt);
        require(ok, "safeTransferFrom failed");
    }
}

contract UnsafeERC20Clean {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    constructor(address t) { token = IERC20(t); }

    function sendTokens(address to, uint256 amt) external {
        token.safeTransfer(to, amt);
    }

    function pullTokens(address from, uint256 amt) external {
        token.safeTransferFrom(from, address(this), amt);
    }
}
