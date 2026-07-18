// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RawTransferFromPositive {
    function deposit(address token, uint256 amount) external {
        IERC20Like(token).transferFrom(msg.sender, address(this), amount);
    }
}
