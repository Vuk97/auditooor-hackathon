// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract VaultInfVuln {
    IERC20 public asset;
    uint256 public totalSupply;

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        totalSupply += shares;
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        totalSupply += shares;
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        shares = convertToShares(assets);
        totalSupply -= shares;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        totalSupply -= shares;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return totalSupply == 0 ? assets : assets * totalSupply / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return totalSupply == 0 ? shares : shares * totalAssets() / totalSupply;
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function previewMint(uint256 shares) external view returns (uint256) {
        return convertToAssets(shares);
    }

    function previewWithdraw(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return convertToAssets(shares);
    }
}