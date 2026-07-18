// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ChainlinkAdapter - thin wrapper around Chainlink price feeds (adapter peripheral)
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

contract ChainlinkAdapter {
    AggregatorV3Interface public feed;
    address public owner;

    constructor(address _feed) {
        feed = AggregatorV3Interface(_feed);
        owner = msg.sender;
    }

    function setOracleFeed(address newFeed) external {
        require(msg.sender == owner, "not owner");
        feed = AggregatorV3Interface(newFeed);
    }

    function latestPrice() external view returns (int256 price, uint256 updatedAt) {
        (, price, , updatedAt,) = feed.latestRoundData();
    }
}
