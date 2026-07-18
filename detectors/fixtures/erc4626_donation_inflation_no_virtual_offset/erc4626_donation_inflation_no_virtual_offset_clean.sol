// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: virtual-offset cushion (VIRTUAL_SHARES / VIRTUAL_ASSETS) added to
// the conversion expression, so a donation cannot inflate the rate.
contract DonationInflationClean {
    uint256 internal totalSupply;
    uint256 internal totalManagedAssets;
    uint256 internal constant VIRTUAL_SHARES = 1;
    uint256 internal constant VIRTUAL_ASSETS = 1;

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero");
        shares = (assets * (totalSupply + VIRTUAL_SHARES))
            / (totalManagedAssets + VIRTUAL_ASSETS);
        totalManagedAssets += assets;
        totalSupply += shares;
    }

    function donate(uint256 assets) external {
        totalManagedAssets += assets;
    }
}
