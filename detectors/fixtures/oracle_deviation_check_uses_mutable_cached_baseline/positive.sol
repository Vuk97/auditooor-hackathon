pragma solidity ^0.8.20;

interface IPriceOracleMutableBaseline {
    function getPrice(address asset) external view returns (uint256);
}

contract MutableCachedBaselinePositive {
    IPriceOracleMutableBaseline public immutable oracle;
    uint256 public cachedPrice;
    uint256 public immutable maxDeviationBps;

    constructor(IPriceOracleMutableBaseline oracle_, uint256 initialPrice, uint256 maxDeviationBps_) {
        oracle = oracle_;
        cachedPrice = initialPrice;
        maxDeviationBps = maxDeviationBps_;
    }

    function updateWeights(address asset) external returns (bool depegged) {
        uint256 currentPrice = oracle.getPrice(asset);
        require(currentPrice > 0, "missing price");

        uint256 deviation = currentPrice > cachedPrice
            ? currentPrice - cachedPrice
            : cachedPrice - currentPrice;
        depegged = deviation * 10_000 > cachedPrice * maxDeviationBps;

        cachedPrice = currentPrice;
    }
}
