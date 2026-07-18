// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FirstDepositTotalsupplyZeroOracleInitClean {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;
    uint256 public constant MIN_INITIAL = 1e6;

    constructor() {
        // Seed dead shares so donation cannot manipulate first deposit.
        totalSupply = MIN_INITIAL;
        balanceOf[address(0)] = MIN_INITIAL;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        uint256 sharePrice = totalAssets * 1e18 / totalSupply;
        shares = sharePrice == 0 ? assets : assets * 1e18 / sharePrice;
        require(shares > 0, "zero shares");
        totalSupply += shares;
        totalAssets += assets;
        balanceOf[msg.sender] += shares;
    }
}
