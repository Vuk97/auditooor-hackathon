// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CachedLiquidityBorrowGatePositive {
    mapping(uint256 => uint128) public cachedLiquidity;
    mapping(address => uint256) public debt;
    uint256 public priceX96 = 2 ** 96;
    uint256 public constant Q96 = 2 ** 96;

    function depositPosition(uint256 tokenId, uint128 liquidity) external {
        cachedLiquidity[tokenId] = liquidity;
    }

    function borrowerCanReduceRealUniswapLiquidityElsewhere(uint256 tokenId) external {
        tokenId;
    }

    function borrowAgainstPosition(uint256 tokenId, uint256 amount) external {
        uint256 collateralValue = uint256(cachedLiquidity[tokenId]) * priceX96 / Q96;
        uint256 borrowLimit = collateralValue * 75 / 100;
        require(borrowLimit >= debt[msg.sender] + amount, "unsafe");
        debt[msg.sender] += amount;
    }
}

contract LiquidationRoundTripProfitPositive {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowShares;
    uint256 public totalBorrowAssets = 1000 ether;
    uint256 public totalBorrowShares = 997 ether;

    function liquidate(address borrower, uint256 seizedAssets)
        external
        returns (uint256 repaidAssets, uint256 repaidShares)
    {
        repaidAssets = toAssetsUp(seizedAssets, totalBorrowAssets, totalBorrowShares);
        repaidShares = toSharesDown(repaidAssets, totalBorrowAssets, totalBorrowShares);

        collateral[borrower] -= seizedAssets;
        collateral[msg.sender] += seizedAssets;
        borrowShares[borrower] -= repaidShares;
    }

    function toAssetsUp(uint256 shares, uint256 assets, uint256 totalShares) internal pure returns (uint256) {
        return (shares * assets + totalShares - 1) / totalShares;
    }

    function toSharesDown(uint256 assets, uint256 totalAssets, uint256 totalShares) internal pure returns (uint256) {
        return assets * totalShares / totalAssets;
    }
}

contract MaxLiquidationInaccuracyPositive {
    struct Position {
        uint256 collateralValue;
        uint256 debtValue;
    }

    function calculateMaxLiquidation(Position memory position)
        internal
        pure
        returns (uint256 maxLiquidableCollateral, uint256 maxLiquidableDebt)
    {
        uint256 liquidationBonus = 11000;
        maxLiquidableCollateral = position.collateralValue * liquidationBonus / 10000;
        maxLiquidableDebt = position.debtValue * 5000 / 1e18;
    }

    function liquidate(Position memory position)
        external
        pure
        returns (uint256 collateralToSeize, uint256 debtToRepay)
    {
        return calculateMaxLiquidation(position);
    }
}
