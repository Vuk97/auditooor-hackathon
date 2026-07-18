// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: withdraw computes shares-to-burn with floor division (rounds down)
// ERC-4626 spec requires rounding UP on withdraw — floor = value leak
// Loss ref: Exactly Protocol ~$7.3M, August 2023
// https://rekt.news/exactly-rekt/
contract VaultVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function deposit(uint256 assets) external {
        uint256 shares = totalSupply == 0 ? assets :
            assets * totalSupply / totalAssets; // round down on deposit — correct
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        totalAssets += assets;
    }

    // VULN: floor division — user burns fewer shares than precise amount
    function withdraw(uint256 assets) external {
        // WRONG: should be mulDivUp — floor allows tiny rounding theft
        uint256 shares = assets * totalSupply / totalAssets; // rounds DOWN
        require(balanceOf[msg.sender] >= shares, "insufficient shares");
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;
    }
}
