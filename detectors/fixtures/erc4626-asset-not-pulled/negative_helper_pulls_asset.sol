// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Upgradeable {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract HelperPullsAssetNegative {
    address public asset;

    function mint(uint256 shares, address receiver) public returns (uint256 assets) {
        assets = shares;
        _deposit(msg.sender, receiver, assets, shares);
    }

    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal {
        IERC20Upgradeable(asset).safeTransferFrom(caller, address(this), assets);
        _mint(receiver, shares);
    }

    function _mint(address, uint256) internal {}
}
