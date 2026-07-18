// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RawTransferPositive {
    IERC20Like public token;

    function withdraw(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
