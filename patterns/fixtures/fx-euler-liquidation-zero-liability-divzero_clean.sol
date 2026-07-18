// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — early-return also covers liabilityValue == 0.
// Source: euler-xyz/euler-vault-kit@2f935f5 (Cantina-43/508 fix)

contract Liquidation {
    struct LiqCache {
        uint256 collateralAdjustedValue;
        uint256 liabilityValue;
        uint256 discount;
    }

    uint256 constant SCALE = 1e18;

    // FIXED: || liabilityValue == 0 prevents division-by-zero
    function checkLiquidation(uint256 collateralAdjustedValue, uint256 liabilityValue)
        internal
        pure
        returns (LiqCache memory cache)
    {
        cache.collateralAdjustedValue = collateralAdjustedValue;
        cache.liabilityValue = liabilityValue;

        // no violation (including zero-debt positions)
        if (collateralAdjustedValue > liabilityValue || liabilityValue == 0) return cache;

        cache.discount = collateralAdjustedValue * SCALE / liabilityValue;
    }
}
