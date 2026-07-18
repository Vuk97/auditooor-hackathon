// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TeleportationBridgeVuln {
    uint256 public maxTransferAmountPerDay = 1_000 ether;
    uint256 public dailyTeleported;

    function teleportBOBA(uint256 amount) external {
        require(dailyTeleported + amount <= maxTransferAmountPerDay, "daily cap");
        dailyTeleported += amount;
    }
}
