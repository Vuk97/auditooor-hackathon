// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

// VULN: updatedAt is ignored — stale price accepted silently
// Loss ref: Venus Protocol ~$200M bad debt, May 2021
// https://rekt.news/venus-blizz-rekt/
contract PriceFeedVuln {
    AggregatorV3Interface public feed;

    constructor(address _feed) { feed = AggregatorV3Interface(_feed); }

    // VULN: discards updatedAt — never checks staleness
    function getPrice() external view returns (uint256) {
        (, int256 answer,,,) = feed.latestRoundData();
        require(answer > 0, "negative price");
        return uint256(answer);  // stale price accepted
    }

    function getCollateralValue(uint256 amount) external view returns (uint256) {
        uint256 price = this.getPrice();
        return amount * price / 1e8;
    }
}
