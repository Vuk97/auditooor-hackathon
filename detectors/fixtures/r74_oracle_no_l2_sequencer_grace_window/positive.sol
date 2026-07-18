// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface R74AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract R74OracleNoL2SequencerGraceWindowPositive {
    R74AggregatorV3Interface internal immutable priceFeed;
    R74AggregatorV3Interface internal immutable sequencerFeed;

    constructor(R74AggregatorV3Interface _priceFeed, R74AggregatorV3Interface _sequencerFeed) {
        priceFeed = _priceFeed;
        sequencerFeed = _sequencerFeed;
    }

    function collateralValue(uint256 amount) external view returns (uint256) {
        (, int256 upAnswer,,,) = sequencerFeed.latestRoundData();
        require(upAnswer == 0, "sequencer down");

        (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(price > 0, "bad price");
        require(updatedAt != 0, "stale");

        return amount * uint256(price) / 1e8;
    }
}
