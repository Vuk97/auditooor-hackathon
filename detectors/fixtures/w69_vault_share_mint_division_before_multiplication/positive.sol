// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransferFrom(address from, address to, uint256 value) external;
}

contract W69VaultShareMintDivisionBeforeMultiplicationPositive {
    IERC20Like public immutable asset;
    uint256 public totalShares;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return 1_000_000 ether;
    }

    function totalSupply() public view returns (uint256) {
        return totalShares;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = assets / totalAssets() * totalSupply();
        asset.safeTransferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function _mint(address, uint256 shares) internal {
        totalShares += shares;
    }
}

