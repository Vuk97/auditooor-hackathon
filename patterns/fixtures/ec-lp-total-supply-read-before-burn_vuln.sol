// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: share price computed from totalSupply BEFORE _burn is called
// Loss ref: Gamma Strategies ~$3.4M, January 2024
// https://rekt.news/gamma-strategies-rekt/
contract LPVaultVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function deposit(uint256 assets) external {
        uint256 shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        totalAssets += assets;
    }

    // VULN: reads totalSupply for price calc BEFORE burning shares
    function redeem(uint256 shares) external returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "insufficient");
        // Uses pre-burn totalSupply — but in scenarios with concurrent txs
        // or manipulated supply, this can be exploited
        assets = shares * totalAssets / totalSupply; // pre-burn totalSupply

        // Burn happens AFTER the price is computed
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares; // too late — price was set above
        totalAssets -= assets;
    }
}
