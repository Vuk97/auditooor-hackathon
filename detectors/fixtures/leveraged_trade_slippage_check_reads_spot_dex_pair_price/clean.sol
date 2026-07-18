pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract LeveragedTradeEngineClean {
    AggregatorV3Interface internal immutable priceFeed;

    constructor(AggregatorV3Interface feed_) {
        priceFeed = feed_;
    }

    function openLong(
        address,
        uint256 collateralAmount,
        uint256 leverage,
        uint256 minAmountOut
    ) external view returns (uint256 amountOut) {
        (, int256 oracleAnswer,,,) = priceFeed.latestRoundData();
        require(oracleAnswer > 0, "bad-price");

        uint256 oraclePrice = uint256(oracleAnswer);
        amountOut = collateralAmount * leverage * 1e8 / oraclePrice;
        require(amountOut >= minAmountOut, "slippage");
    }
}
