// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — both liquidity and _totalAssets decremented together.
// Source: silo-finance/silo-contracts-v2@107f6bd

contract SiloERC4626Lib {
    // FIXED: both liquidity and _totalAssets adjusted for consistent rounding
    function maxWithdraw(
        uint256 liquidity,
        uint256 _totalAssets,
        uint256 totalShares
    ) internal pure returns (uint256 assets, uint256 shares) {
        if (liquidity != 0) {
            unchecked { liquidity -= 1; _totalAssets -= 1; }
        }
        shares = liquidity * totalShares / _totalAssets;
        assets = shares * _totalAssets / totalShares;
    }
}
