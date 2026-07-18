// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — maxWithdraw adjusts liquidity but not _totalAssets.
// Source: silo-finance/silo-contracts-v2@107f6bd

contract SiloERC4626Lib {
    // VULNERABLE: only liquidity is decremented, _totalAssets is not
    function maxWithdraw(
        uint256 liquidity,
        uint256 _totalAssets,
        uint256 totalShares
    ) internal pure returns (uint256 assets, uint256 shares) {
        if (liquidity != 0) {
            // Accounts for rounding in share conversion
            unchecked { liquidity -= 1; }
            // BUG: _totalAssets not adjusted — convertToShares uses stale totalAssets
        }
        // convertToShares uses _totalAssets which is 1 too high relative to liquidity
        shares = liquidity * totalShares / _totalAssets; // over-estimates shares
        assets = shares * _totalAssets / totalShares;
    }
}
