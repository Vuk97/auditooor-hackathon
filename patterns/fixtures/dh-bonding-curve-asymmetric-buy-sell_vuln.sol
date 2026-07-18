// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BondingAsymmetricVuln {
    uint256 public reserve;
    uint256 public totalSupply;
    uint256 public theta = 95;
    uint256 public k = 5;
    function getPurchasePrice(uint256 amt) external view returns (uint256) {
        return (amt * theta * reserve) / totalSupply;
    }
    function getSalePrice(uint256 amt) external view returns (uint256) {
        return (amt * (theta + k) * reserve) / totalSupply;
    }
}
