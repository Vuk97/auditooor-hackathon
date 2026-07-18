// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — liquidation missing zero liabilityValue guard.
// Source: euler-xyz/euler-vault-kit@2f935f5 (Cantina-43/508 fix)

contract Liquidation {
    struct LiqCache {
        uint256 collateralAdjustedValue;
        uint256 liabilityValue;
        uint256 discount;
    }

    uint256 constant SCALE = 1e18;

    // VULNERABLE: if liabilityValue == 0 and collateralAdjustedValue == 0,
    // falls through to division by zero on liabilityValue
    function checkLiquidation(uint256 collateralAdjustedValue, uint256 liabilityValue)
        internal
        pure
        returns (LiqCache memory cache)
    {
        cache.collateralAdjustedValue = collateralAdjustedValue;
        cache.liabilityValue = liabilityValue;

        // no violation — but misses liabilityValue == 0 case
        if (collateralAdjustedValue > liabilityValue) return cache;

        // Compute discount — PANICS if liabilityValue == 0
        cache.discount = collateralAdjustedValue * SCALE / liabilityValue;
    }
}
