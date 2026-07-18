// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// VULN: totalAssets() = balanceOf(this) — direct donations inflate share price
// Loss ref: Euler Finance donateToReserves ~$197M, March 2023
// https://rekt.news/euler-rekt/
contract DonationVaultVuln {
    IERC20 public token;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor(address _token) { token = IERC20(_token); }

    // VULN: raw balanceOf — any direct transfer inflates this
    function totalAssets() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return token.balanceOf(address(this)) * 1e18 / totalShares; // manipulable
    }

    function deposit(uint256 assets) external {
        uint256 ts = totalShares;
        uint256 ta = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), assets);
        uint256 minted = ts == 0 ? assets : assets * ts / ta;
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}
