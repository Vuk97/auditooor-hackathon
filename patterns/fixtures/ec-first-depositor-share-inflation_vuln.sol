// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// VULN: first depositor inflation — no dead shares burned, totalAssets = balanceOf
// Loss ref: Sonne Finance ~$20M, May 2024
// https://rekt.news/sonne-finance-rekt/
contract VaultInflationVuln {
    IERC20 public token;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor(address _token) { token = IERC20(_token); }

    function totalAssets() public view returns (uint256) {
        return token.balanceOf(address(this)); // VULN: includes direct donations
    }

    // VULN: totalSupply==0 branch mints 1:1 with no dead-share burn
    function deposit(uint256 assets) external returns (uint256 minted) {
        token.transferFrom(msg.sender, address(this), assets);
        if (totalShares == 0) {
            minted = assets; // first depositor gets 1:1
        } else {
            minted = assets * totalShares / (totalAssets() - assets); // donation-inflated
        }
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}
