// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

// CLEAN: oracle price normalized to 18 decimals before use
contract OracleDecimalsClean {
    AggregatorV3Interface public feed;

    constructor(address _feed) { feed = AggregatorV3Interface(_feed); }

    // CLEAN: normalizes 8-dec Chainlink price to 18-dec before multiplication
    function getCollateralValue(uint256 tokenAmount) external view returns (uint256) {
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0, "bad price");
        uint8 feedDecimals = feed.decimals(); // query dynamically — handle non-8 feeds
        // Normalize: price * 10^(18 - feedDecimals) to get 18-dec price
        uint256 normalizedPrice = uint256(price) * (10 ** (18 - feedDecimals));
        return tokenAmount * normalizedPrice / 1e18; // result in 18 decimals
    }
}
