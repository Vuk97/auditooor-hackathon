pragma solidity ^0.8.20;

interface IPriceOracleStableAnchor {
    function getPrice(address asset) external view returns (uint256);
}

contract MutableCachedBaselineClean {
    IPriceOracleStableAnchor public immutable oracle;
    uint256 public lastObservedPrice;
    uint256 public immutable pegAnchorPrice;
    uint256 public immutable maxDeviationBps;

    constructor(
        IPriceOracleStableAnchor oracle_,
        uint256 initialObservedPrice,
        uint256 pegAnchorPrice_,
        uint256 maxDeviationBps_
    ) {
        oracle = oracle_;
        lastObservedPrice = initialObservedPrice;
        pegAnchorPrice = pegAnchorPrice_;
        maxDeviationBps = maxDeviationBps_;
    }

    function updateWeights(address asset) external returns (bool depegged) {
        uint256 currentPrice = oracle.getPrice(asset);
        require(currentPrice > 0, "missing price");

        uint256 deviation = currentPrice > pegAnchorPrice
            ? currentPrice - pegAnchorPrice
            : pegAnchorPrice - currentPrice;
        depegged = deviation * 10_000 > pegAnchorPrice * maxDeviationBps;

        lastObservedPrice = currentPrice;
    }
}
