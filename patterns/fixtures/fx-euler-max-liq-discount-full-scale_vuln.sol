// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — setMaxLiquidationDiscount allows CONFIG_SCALE (100%) which
// causes division by zero in liquidation bonus computation.
// Source: euler-xyz/euler-vault-kit@3f9468d (Cantina-520 fix)

contract Governance {
    uint16 public maxLiquidationDiscount;
    uint256 constant CONFIG_SCALE = 1e4;

    error E_BadValue();

    // VULNERABLE: allows newDiscount == CONFIG_SCALE (10000)
    function setMaxLiquidationDiscount(uint16 newDiscount) external {
        maxLiquidationDiscount = newDiscount;
    }

    // Called during liquidation — will panic if maxLiquidationDiscount == CONFIG_SCALE
    function computeBonus(uint256 collateral) external view returns (uint256) {
        uint256 discount = maxLiquidationDiscount;
        // Division by zero if discount == CONFIG_SCALE
        return collateral * discount / (CONFIG_SCALE - discount);
    }
}
