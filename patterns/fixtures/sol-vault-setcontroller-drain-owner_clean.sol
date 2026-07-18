// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultControllerClean {
    address public owner = msg.sender;
    address public controller;
    address public pendingController;
    uint256 public pendingSince;
    uint256 public constant MIN_DELAY = 2 days;

    function setPendingController(address c) external {
        require(msg.sender == owner);
        pendingController = c;
        pendingSince = block.timestamp;
    }
    function acceptController() external {
        require(pendingController != address(0));
        require(block.timestamp >= pendingSince + MIN_DELAY, "timelock");
        controller = pendingController;
        pendingController = address(0);
    }
}
