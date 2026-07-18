// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FirstDepositTotalsupplyZeroOracleInitVuln {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;

    function oraclePrice() public pure returns (uint256) { return 1e18; }

    function deposit(uint256 assets) external returns (uint256 shares) {
        if (totalSupply == 0) {
            shares = assets * oraclePrice() / 1e18;
        } else {
            uint256 sharePrice = totalAssets * 1e18 / totalSupply;
            // VULN: donation manipulates sharePrice; shares can round to 0 with no floor.
            shares = assets * 1e18 / sharePrice;
        }
        totalSupply += shares;
        totalAssets += assets;
        balanceOf[msg.sender] += shares;
    }

    function donate(uint256 amount) external { totalAssets += amount; }
}
