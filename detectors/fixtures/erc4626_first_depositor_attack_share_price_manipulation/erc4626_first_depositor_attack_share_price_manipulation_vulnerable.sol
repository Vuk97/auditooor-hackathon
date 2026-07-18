// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC4626FirstDepositorAttackSharePriceManipulationVulnerable {
    uint256 internal totalSupply;
    uint256 internal totalManagedAssets;

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero assets");
        if (totalSupply == 0) {
            shares = assets;
        } else {
            shares = (assets * totalSupply) / totalManagedAssets;
        }
        totalManagedAssets += assets;
        totalSupply += shares;
    }

    function donate(uint256 assets) external {
        totalManagedAssets += assets;
    }
}
