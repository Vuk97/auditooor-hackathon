// SPDX-License-Identifier: MIT
// Fixture: callback_reentrancy_no_guard — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4);
}

interface IERC1155 {
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external;
}

contract CallbackReentrancyVuln is IERC1155Receiver {
    uint256 public balance;
    IERC1155 public token;

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    // VULN: external call at line N, state write at line N+1.
    // Attacker reentering in onERC1155Received observes stale `balance`.
    function deposit(uint256 id, uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), id, amount, "");
        balance += amount;
    }
}
