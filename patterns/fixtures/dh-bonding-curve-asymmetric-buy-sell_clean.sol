// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BondingAsymmetricClean {
    uint256 public reserve;
    uint256 public totalSupply;
    uint256 public feeBps = 30; // 0.3%
    function _price(uint256 amt) internal view returns (uint256) {
        return (amt * reserve) / totalSupply;
    }
    function getPurchasePrice(uint256 amt) external view returns (uint256) { return _price(amt); }
    function getSalePrice(uint256 amt) external view returns (uint256) { return _price(amt) * (10000 - feeBps) / 10000; }
}
