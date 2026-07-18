// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BondingCurveBuySellInverseMismatchVuln {
    uint256 public reserve = 100 ether;
    uint256 public totalSupply = 100 ether;
    uint256 public constant theta = 1e18;

    // VULN: buy uses reserve / supply, sell uses supply / reserve — not inverses.
    function buy(uint256 amount) external payable returns (uint256 shares) {
        shares = amount * theta * reserve / totalSupply / 1e18;
        totalSupply += shares;
        reserve += amount;
    }

    function sell(uint256 shares) external returns (uint256 amount) {
        amount = shares * theta * totalSupply / reserve / 1e18;
        totalSupply -= shares;
        reserve -= amount;
    }
}
