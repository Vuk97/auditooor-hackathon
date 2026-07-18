// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TeleportationBridgeClean {
    uint256 public maxTransferAmountPerDay = 1_000 ether;
    uint256 public dailyTeleported;

    function updateDailyLimit() internal {
        if (dailyTeleported > maxTransferAmountPerDay) {
            dailyTeleported = maxTransferAmountPerDay;
        }
    }

    function teleportBOBA(uint256 amount) external {
        updateDailyLimit();
        require(dailyTeleported + amount <= maxTransferAmountPerDay, "daily cap");
        dailyTeleported += amount;
    }
}
