// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FreezingOfUsersFundsDueToExcessiveFeeSettingsClean {
    uint256 public reserveFeeBps;
    uint256 public maxReserveFeeBps = 10_000;

    function configureVaultDepositFee(uint256 newReserveFeeBps) external {
        require(newReserveFeeBps <= maxReserveFeeBps, "reserve fee cap");
        reserveFeeBps = newReserveFeeBps;
    }
}
