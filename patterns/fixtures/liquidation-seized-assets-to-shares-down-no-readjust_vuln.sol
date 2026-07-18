// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LiquidationSeizedAssetsToSharesDownNoReadjustVuln {
    uint256 public totalBorrowAssets = 1_000_000;
    uint256 public totalBorrowShares = 900_000;
    uint256 public collateralPrice = 1e36;
    uint256 public constant ORACLE_PRICE_SCALE = 1e36;
    uint256 public liquidationIncentiveFactor = 1.05e18;

    function liquidate(address borrower, uint256 seizedAssets)
        external
        returns (uint256 repaidAssets, uint256 repaidShares)
    {
        borrower;

        if (seizedAssets > 0) {
            repaidAssets = mulDivUp(seizedAssets, collateralPrice, ORACLE_PRICE_SCALE);
            repaidAssets = wDivUp(repaidAssets, liquidationIncentiveFactor);
            repaidShares = toSharesDown(repaidAssets, totalBorrowAssets, totalBorrowShares);
        }

        totalBorrowShares -= repaidShares;
    }

    function toSharesDown(uint256 assets, uint256 totalAssets, uint256 totalShares) internal pure returns (uint256) {
        return assets * totalShares / totalAssets;
    }

    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        return (x * y + d - 1) / d;
    }

    function wDivUp(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * 1e18 + y - 1) / y;
    }
}
