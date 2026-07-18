// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: shares burned BEFORE computing asset output
contract LPVaultClean {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function deposit(uint256 assets) external {
        uint256 shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        totalAssets += assets;
    }

    // CLEAN: burn shares first, compute assets from post-burn state
    function redeem(uint256 shares) external returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "insufficient");

        // Burn FIRST
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;

        // Now compute assets from post-burn totalSupply + totalAssets
        // (totalAssets is pre-reduction here, totalSupply is post-burn)
        assets = shares * totalAssets / (totalSupply + shares); // use original supply for ratio
        totalAssets -= assets;
    }
}
