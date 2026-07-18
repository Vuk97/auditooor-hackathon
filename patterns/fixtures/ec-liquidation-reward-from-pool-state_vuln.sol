// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC4626 {
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

// VULN: liquidation bonus computed from manipulable vault totalAssets
// Loss ref: Euler Finance ~$197M, March 2023 (donation + liquidation)
// https://rekt.news/euler-rekt/
contract LiquidationVuln {
    IERC4626 public vault;
    mapping(address => uint256) public shares; // LP shares as collateral
    mapping(address => uint256) public debt;

    uint256 public constant BONUS_BPS = 1000; // 10% bonus

    constructor(address _vault) { vault = IERC4626(_vault); }

    // VULN: bonus computed from live totalAssets — donation-manipulable
    function liquidate(address borrower, uint256 repayAmount) external {
        require(debt[borrower] > 0, "no debt");

        // Uses live pool state — attacker can inflate via direct donation
        uint256 assetPerShare = vault.totalAssets() * 1e18 / vault.totalSupply();
        uint256 collateralValue = shares[borrower] * assetPerShare / 1e18;

        // bonus derived from manipulated collateralValue
        uint256 bonus = collateralValue * BONUS_BPS / 10000;
        uint256 seize = repayAmount + bonus; // over-seizes after donation

        debt[borrower] -= repayAmount;
        shares[borrower] -= seize * vault.totalSupply() / vault.totalAssets();
    }
}
