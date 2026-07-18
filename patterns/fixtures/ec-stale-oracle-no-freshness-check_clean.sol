// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

// CLEAN: updatedAt freshness check enforced
contract PriceFeedClean {
    AggregatorV3Interface public feed;
    uint256 public constant MAX_STALENESS = 3600; // 1 hour max

    constructor(address _feed) { feed = AggregatorV3Interface(_feed); }

    // CLEAN: validates updatedAt against block.timestamp
    function getPrice() external view returns (uint256) {
        (uint80 roundId, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
        require(answer > 0, "negative price");
        require(roundId > 0, "invalid round");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale price");
        return uint256(answer);
    }

    function getCollateralValue(uint256 amount) external view returns (uint256) {
        uint256 price = this.getPrice();
        return amount * price / 1e8;
    }
}
