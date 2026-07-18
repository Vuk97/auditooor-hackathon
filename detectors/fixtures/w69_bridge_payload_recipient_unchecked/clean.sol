// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransfer(address to, uint256 value) external;
}

contract W69BridgePayloadRecipientUncheckedClean {
    error InvalidRecipient();

    IERC20Like public immutable token;
    mapping(uint256 => address) public expectedRecipient;

    constructor(IERC20Like token_) {
        token = token_;
    }

    function lzReceive(bytes calldata payload) external {
        (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
        if (recipient == address(0)) revert InvalidRecipient();
        if (recipient != expectedRecipient[block.chainid]) revert InvalidRecipient();
        token.safeTransfer(recipient, amount);
    }
}

