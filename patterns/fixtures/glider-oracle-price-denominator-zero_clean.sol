// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IChainlinkAggregator {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract VaultClean {
    IChainlinkAggregator public priceFeed;

    constructor(address _priceFeed) {
        priceFeed = IChainlinkAggregator(_priceFeed);
    }

    function convertToShares(uint256 assets) external view returns (uint256 shares) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        uint256 price = uint256(answer);
        require(price > 0, "invalid price");
        shares = assets / price;
    }
}