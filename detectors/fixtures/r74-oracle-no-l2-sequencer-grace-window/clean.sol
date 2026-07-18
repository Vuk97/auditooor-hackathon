// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface R74CleanAggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract R74OracleNoL2SequencerGraceWindowClean {
    uint256 internal constant GRACE_PERIOD = 3600;

    R74CleanAggregatorV3Interface internal immutable priceFeed;
    R74CleanAggregatorV3Interface internal immutable sequencerFeed;

    constructor(R74CleanAggregatorV3Interface _priceFeed, R74CleanAggregatorV3Interface _sequencerFeed) {
        priceFeed = _priceFeed;
        sequencerFeed = _sequencerFeed;
    }

    function collateralValue(uint256 amount) external view returns (uint256) {
        (, int256 upAnswer, uint256 startedAt,,) = sequencerFeed.latestRoundData();
        require(upAnswer == 0, "sequencer down");
        require(block.timestamp - startedAt > GRACE_PERIOD, "wait");

        (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(price > 0, "bad price");
        require(updatedAt != 0, "stale");

        return amount * uint256(price) / 1e8;
    }
}
