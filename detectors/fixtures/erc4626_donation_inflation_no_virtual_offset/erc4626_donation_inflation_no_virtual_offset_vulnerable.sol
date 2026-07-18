// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: donation sink + raw share math, no virtual offset.
contract DonationInflationVulnerable {
    uint256 internal totalSupply;
    uint256 internal totalManagedAssets;

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero");
        shares = (assets * totalSupply) / totalManagedAssets;
        totalManagedAssets += assets;
        totalSupply += shares;
    }

    // donation sink: assets enter accounting with no share mint.
    function donate(uint256 assets) external {
        totalManagedAssets += assets;
    }
}
