// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransfer(address to, uint256 value) external;
}

contract W69BridgePayloadRecipientUncheckedPositive {
    IERC20Like public immutable token;

    constructor(IERC20Like token_) {
        token = token_;
    }

    function lzReceive(bytes calldata payload) external {
        (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
        token.safeTransfer(recipient, amount);
    }
}

