// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MpEthVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function depositETH(address receiver) external payable returns (uint256 shares) {
        shares = msg.value; // 1:1 for simplicity
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    // Vuln: credits shares without collecting the underlying asset.
    function mint(uint256 shares, address receiver) external {
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }
}
