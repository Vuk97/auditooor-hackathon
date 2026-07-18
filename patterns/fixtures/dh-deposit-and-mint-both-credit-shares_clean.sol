// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAsset {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract MpEthClean {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    IAsset public asset;

    function depositETH(address receiver) external payable returns (uint256 shares) {
        shares = msg.value;
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    // Clean: mint pulls the underlying `assets` via transferFrom before
    // crediting shares. 1:1 rate for the fixture.
    function mint(uint256 shares, address receiver) external {
        uint256 assets = shares;
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }
}
