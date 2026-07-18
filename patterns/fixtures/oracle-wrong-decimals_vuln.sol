// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAggregator {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

contract OracleWrongDecimalsVuln {
    IAggregator public priceFeed;

    constructor(address feed) {
        priceFeed = IAggregator(feed);
    }

    // VULN: consumes `latestAnswer()` and divides by a hardcoded 1e8 without
    // checking priceFeed.decimals(). Works for ETH/USD (8 decimals) but
    // silently miscomputes for AMPL/USD (18) or certain stablecoin feeds (6).
    function getCollateralValueUsd(uint256 amount) external view returns (uint256) {
        int256 price = priceFeed.latestAnswer();
        return (amount * uint256(price)) / 1e8;
    }

    // VULN: latestRoundData used with `10 ** 8` hardcoded scaling.
    function quote(uint256 amount) external view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return (amount * uint256(price)) / (10 ** 8);
    }
}
