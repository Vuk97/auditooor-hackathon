// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// Minimal SafeERC20-style library: each wrapper checks the return and reverts on
// failure, so a caller of safeTransfer/safeTransferFrom is NEVER flagged (the
// wrapper consumes the bool return).
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "SafeERC20: transfer failed");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        require(token.transferFrom(from, to, amount), "SafeERC20: transferFrom failed");
    }
}

// NOT FLAGGED: uses SafeERC20.safeTransfer (a revert-on-failure wrapper).
contract SafeErc20Clean {
    using SafeERC20 for IERC20;

    IERC20 public token;

    function pay(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }
}
