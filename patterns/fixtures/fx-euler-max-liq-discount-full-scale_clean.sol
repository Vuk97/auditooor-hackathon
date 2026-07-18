// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — setMaxLiquidationDiscount rejects CONFIG_SCALE.
// Source: euler-xyz/euler-vault-kit@3f9468d (Cantina-520 fix)

contract Governance {
    uint16 public maxLiquidationDiscount;
    uint256 constant CONFIG_SCALE = 1e4;

    error E_BadMaxLiquidationDiscount();

    // FIXED: rejects value that would cause division by zero downstream
    function setMaxLiquidationDiscount(uint16 newDiscount) external {
        if (newDiscount == CONFIG_SCALE) revert E_BadMaxLiquidationDiscount();
        maxLiquidationDiscount = newDiscount;
    }

    function computeBonus(uint256 collateral) external view returns (uint256) {
        uint256 discount = maxLiquidationDiscount;
        return collateral * discount / (CONFIG_SCALE - discount);
    }
}
