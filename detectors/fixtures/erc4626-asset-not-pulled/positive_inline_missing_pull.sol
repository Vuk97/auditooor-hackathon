// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InlineMissingPullPositive {
    function mint(uint256 shares, address receiver) public returns (uint256 assets) {
        assets = shares;
        _mint(receiver, shares);
    }

    function _mint(address, uint256) internal {}
}
