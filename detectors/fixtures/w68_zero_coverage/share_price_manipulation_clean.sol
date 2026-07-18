// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: tracked internal accounting, immune to direct donation.
contract SharePriceManipulationSafe {
    uint256 public totalShares;
    uint256 public trackedAssets;

    function depositConvert(uint256 assets, address) external view returns (uint256) {
        if (totalShares == 0) return assets;
        return assets * totalShares / trackedAssets;
    }
}
