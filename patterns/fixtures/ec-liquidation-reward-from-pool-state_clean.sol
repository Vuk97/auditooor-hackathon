// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

// CLEAN: liquidation bonus from Chainlink oracle, not live pool state
contract LiquidationClean {
    AggregatorV3Interface public oracle;
    mapping(address => uint256) public collateralTokens;
    mapping(address => uint256) public debt;

    uint256 public constant BONUS_BPS = 1000;
    uint256 public constant MAX_STALENESS = 3600;

    constructor(address _oracle) { oracle = AggregatorV3Interface(_oracle); }

    // CLEAN: uses Chainlink price — not manipulable via donation
    function liquidate(address borrower, uint256 repayAmount) external {
        require(debt[borrower] > 0, "no debt");

        (, int256 answer,, uint256 updatedAt,) = oracle.latestRoundData();
        require(answer > 0 && block.timestamp - updatedAt <= MAX_STALENESS, "bad price");

        uint256 price = uint256(answer) * 1e10;
        uint256 collateralValue = collateralTokens[borrower] * price / 1e18;
        uint256 bonus = repayAmount * BONUS_BPS / 10000; // bonus based on DEBT, not collateral
        uint256 seize = repayAmount + bonus;

        require(seize <= collateralValue, "seize exceeds collateral");
        debt[borrower] -= repayAmount;
        collateralTokens[borrower] -= seize * 1e18 / price;
    }
}
