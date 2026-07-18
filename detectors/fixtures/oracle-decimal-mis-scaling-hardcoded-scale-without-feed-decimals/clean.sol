// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function decimals() external view returns (uint8);

    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

contract OracleDecimalMisScalingHardcodedScaleWithoutFeedDecimalsClean {
    AggregatorV3Interface public immutable priceFeed;

    constructor(AggregatorV3Interface newPriceFeed) {
        priceFeed = newPriceFeed;
    }

    function quoteCollateralValue(uint256 collateralAmount) external view returns (uint256) {
        (, int256 answer,,,) = priceFeed.latestRoundData();
        require(answer > 0, "bad price");

        uint256 oraclePrice = uint256(answer);
        uint8 feedDecimals = priceFeed.decimals();
        return collateralAmount * oraclePrice / (10 ** uint256(feedDecimals));
    }
}
