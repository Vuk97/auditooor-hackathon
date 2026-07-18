// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: ERC4626 share price used as collateral oracle without manipulation guards
// Pattern: convertToAssets() called in price/oracle/value function with no TWAP or supply floor
// Real-world analogs: ResupplyFi (Jun 2025), Euler Finance (Mar 2023), Radiant Capital (Jan 2024)

interface IERC4626 {
    function convertToAssets(uint256 shares) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract CollateralOracleVuln {
    IERC4626 public vault;
    mapping(address => uint256) public collateralShares;
    mapping(address => uint256) public debtBalance;
    uint256 public constant LTV = 8000; // 80%

    // VULN: getPrice reads convertToAssets without supply floor or TWAP
    // An attacker can inflate vault share price via flashloan donation attack
    function getPrice(address user) external view returns (uint256) {
        uint256 shares = collateralShares[user];
        return vault.convertToAssets(shares);
    }

    // VULN: collateral value computed directly from manipulable share price
    function collateralValue(uint256 shares) external view returns (uint256) {
        return vault.convertToAssets(shares);
    }
}
