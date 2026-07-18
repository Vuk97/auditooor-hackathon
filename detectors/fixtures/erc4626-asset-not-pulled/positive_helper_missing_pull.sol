// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HelperMissingPullPositive {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = assets;
        _deposit(msg.sender, receiver, assets, shares);
    }

    function _deposit(address, address receiver, uint256, uint256 shares) internal {
        _mint(receiver, shares);
    }

    function _mint(address, uint256) internal {}
}
