// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FreezingOfUsersFundsDueToExcessiveFeeSettingsVulnerable {
    uint256 public reserveFeeBps;
    uint256 public maxReserveFeeBps = 10_000;

    function configureVaultDepositFee(uint256 newReserveFeeBps) external {
        reserveFeeBps = newReserveFeeBps;
    }
}
