// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC4626FirstDepositorAttackSharePriceManipulationClean {
    uint256 internal totalSupply;
    uint256 internal totalManagedAssets;
    uint256 internal constant VIRTUAL_ASSETS = 1;
    uint256 internal constant VIRTUAL_SHARES = 1;

    function deposit(uint256 assets) external returns (uint256 shares) {
        _bootstrapVirtualOffset();
        require(assets > 0, "zero assets");
        shares = (assets * (totalSupply + VIRTUAL_SHARES)) / (totalManagedAssets + VIRTUAL_ASSETS);
        totalManagedAssets += assets;
        totalSupply += shares;
    }

    function donate(uint256 assets) external {
        totalManagedAssets += assets;
    }

    function _bootstrapVirtualOffset() internal pure {}
}
