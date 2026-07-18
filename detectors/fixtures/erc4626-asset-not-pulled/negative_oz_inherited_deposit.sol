// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC4626Upgradeable {
    function _deposit(address, address, uint256, uint256) internal virtual {}
}

contract OzInheritedDepositNegative is ERC4626Upgradeable {
    function mint(uint256 shares, address receiver) public returns (uint256 assets) {
        assets = shares;
        _deposit(msg.sender, receiver, assets, shares);
    }
}
