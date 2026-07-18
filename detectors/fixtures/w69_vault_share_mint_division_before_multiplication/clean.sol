// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransferFrom(address from, address to, uint256 value) external;
}

library Math {
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256) {
        return (x * y) / denominator;
    }
}

contract W69VaultShareMintDivisionBeforeMultiplicationClean {
    error ZeroShares();

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
        shares = Math.mulDiv(assets, totalSupply(), totalAssets());
        if (shares == 0) revert ZeroShares();
        asset.safeTransferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function _mint(address, uint256 shares) internal {
        totalShares += shares;
    }
}

