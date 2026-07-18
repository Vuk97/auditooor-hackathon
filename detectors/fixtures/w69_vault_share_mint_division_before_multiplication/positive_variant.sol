// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20LikeVariant {
    function safeTransferFrom(address from, address to, uint256 value) external;
}

contract W69VaultShareMintDivisionBeforeMultiplicationPositiveVariant {
    IERC20LikeVariant public immutable asset;
    uint256 public totalShares;

    constructor(IERC20LikeVariant asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return 5_000_000 ether;
    }

    function totalSupply() public view returns (uint256) {
        return totalShares;
    }

    function depositFor(uint256 depositAmount, address recipient) external returns (uint256 mintAmount) {
        mintAmount = depositAmount / totalAssets() * totalSupply();
        asset.safeTransferFrom(msg.sender, address(this), depositAmount);
        _mint(recipient, mintAmount);
    }

    function _mint(address, uint256 shares) internal {
        totalShares += shares;
    }
}
