// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BondingCurveBuySellInverseMismatchClean {
    uint256 public reserve = 100 ether;
    uint256 public totalSupply = 100 ether;

    function _price(uint256 amount, uint256 _reserve, uint256 _supply) internal pure returns (uint256) {
        // Shared curve: constant-product-style; invertible.
        return amount * _supply / (_reserve + amount);
    }

    function buy(uint256 amount) external payable returns (uint256 shares) {
        shares = _price(amount, reserve, totalSupply);
        totalSupply += shares;
        reserve += amount;
    }

    function sell(uint256 shares) external returns (uint256 amount) {
        // Inverse of _price: solve for amount in shares = amount*supply/(reserve+amount).
        amount = shares * reserve / (totalSupply - shares);
        totalSupply -= shares;
        reserve -= amount;
    }
}
