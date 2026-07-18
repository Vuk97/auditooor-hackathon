// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface INonfungiblePositionManagerLike {
    function positions(uint256 tokenId) external view returns (uint128 liquidity);
}

contract FreshLiquidityBorrowGateClean {
    INonfungiblePositionManagerLike public immutable positionManager;
    mapping(address => uint256) public debt;
    uint256 public priceX96 = 2 ** 96;
    uint256 public constant Q96 = 2 ** 96;

    constructor(INonfungiblePositionManagerLike manager) {
        positionManager = manager;
    }

    function borrowAgainstPosition(uint256 tokenId, uint256 amount) external {
        uint128 liveLiquidity = positionManager.positions(tokenId);
        uint256 collateralValue = uint256(liveLiquidity) * priceX96 / Q96;
        uint256 borrowLimit = collateralValue * 75 / 100;
        require(borrowLimit >= debt[msg.sender] + amount, "unsafe");
        debt[msg.sender] += amount;
    }
}

contract LiquidationRoundTripReadjustClean {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowShares;
    uint256 public totalBorrowAssets = 1000 ether;
    uint256 public totalBorrowShares = 997 ether;

    function liquidate(address borrower, uint256 seizedAssets)
        external
        returns (uint256 repaidAssets, uint256 repaidShares)
    {
        repaidAssets = toAssetsUp(seizedAssets, totalBorrowAssets, totalBorrowShares);
        repaidShares = toSharesUp(repaidAssets, totalBorrowAssets, totalBorrowShares);
        repaidAssets = toAssetsUp(repaidShares, totalBorrowAssets, totalBorrowShares);

        collateral[borrower] -= seizedAssets;
        collateral[msg.sender] += seizedAssets;
        borrowShares[borrower] -= repaidShares;
    }

    function toAssetsUp(uint256 shares, uint256 assets, uint256 totalShares) internal pure returns (uint256) {
        return (shares * assets + totalShares - 1) / totalShares;
    }

    function toSharesUp(uint256 assets, uint256 totalAssets, uint256 totalShares) internal pure returns (uint256) {
        return (assets * totalShares + totalAssets - 1) / totalAssets;
    }
}

contract MaxLiquidationInaccuracyClean {
    struct Position {
        uint256 collateralValue;
        uint256 debtValue;
        uint256 debtAmount;
        uint256 collateralAmount;
    }

    function calculateMaxLiquidation(Position memory position, uint256 oracleScale)
        internal
        pure
        returns (uint256 maxLiquidableCollateral, uint256 maxLiquidableDebt)
    {
        uint256 normalizedCollateral = normalizeValue(position.collateralValue, oracleScale);
        uint256 normalizedDebt = normalizeValue(position.debtValue, oracleScale);
        maxLiquidableCollateral = min(normalizedCollateral * 11000 / 10000, position.collateralAmount);
        maxLiquidableDebt = min(normalizedDebt * 5000 / 10000, position.debtAmount);
    }

    function liquidate(Position memory position, uint256 oracleScale)
        external
        pure
        returns (uint256 collateralToSeize, uint256 debtToRepay)
    {
        return calculateMaxLiquidation(position, oracleScale);
    }

    function normalizeValue(uint256 value, uint256 oracleScale) internal pure returns (uint256) {
        return value * 1e18 / oracleScale;
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
