// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CometRiskParameterClean {
    uint64 internal constant FACTOR_SCALE = 1e18;

    uint64 public liquidationFactor;
    uint64 public storeFrontPriceFactor;

    constructor() {
        liquidationFactor = 0.90e18;
        storeFrontPriceFactor = 0.97e18;
    }

    function setLiquidationFactor(uint64 newLiquidationFactor) external {
        require(newLiquidationFactor <= FACTOR_SCALE, "factor");
        require(newLiquidationFactor < storeFrontPriceFactor, "no-loss");
        liquidationFactor = newLiquidationFactor;
    }

    function setStoreFrontPriceFactor(uint64 newStoreFrontPriceFactor) external {
        require(newStoreFrontPriceFactor <= FACTOR_SCALE, "store-front");
        require(liquidationFactor < newStoreFrontPriceFactor, "no-loss");
        storeFrontPriceFactor = newStoreFrontPriceFactor;
    }

    function quoteLiquidatorPayout(uint256 collateralValue) external view returns (uint256) {
        return collateralValue * storeFrontPriceFactor / FACTOR_SCALE;
    }
}
