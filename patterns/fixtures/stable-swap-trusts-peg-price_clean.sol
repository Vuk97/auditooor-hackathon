// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IChainlinkFeed {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

// CLEAN: the same lending helper now prices stablecoins through a live
// Chainlink feed. Depeg events are reflected in the returned value, so
// collateral valuation tracks reality.
contract StablePegPriceClean {
    mapping(address => IChainlinkFeed) public priceFeed;

    function setFeed(address token, IChainlinkFeed feed) external {
        priceFeed[token] = feed;
    }

    function getStablePrice(address token) external view returns (uint256) {
        IChainlinkFeed feed = priceFeed[token];
        require(address(feed) != address(0), "no feed");
        (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
        require(answer > 0, "bad price");
        require(block.timestamp - updatedAt <= 1 hours, "stale");
        return uint256(answer);
    }

    function valueStableCollateral(address token, uint256 amount)
        external
        view
        returns (uint256)
    {
        IChainlinkFeed feed = priceFeed[token];
        (, int256 answer,,,) = feed.latestRoundData();
        require(answer > 0, "bad price");
        return uint256(answer) * amount;
    }
}
