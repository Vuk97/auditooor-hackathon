// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAggregator {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

contract OracleWrongDecimalsClean {
    IAggregator public priceFeed;

    constructor(address feed) {
        priceFeed = IAggregator(feed);
    }

    // CLEAN: reads priceFeed.decimals() and normalises dynamically.
    // The presence of `.decimals()` in the body suppresses the detector.
    function getCollateralValueUsd(uint256 amount) external view returns (uint256) {
        int256 price = priceFeed.latestAnswer();
        uint256 feedDecimals = uint256(priceFeed.decimals());
        return (amount * uint256(price)) / (10 ** feedDecimals);
    }

    // CLEAN: uses latestRoundData with decimals() normalisation.
    function quote(uint256 amount) external view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        uint256 feedDecimals = uint256(priceFeed.decimals());
        return (amount * uint256(price)) / (10 ** feedDecimals);
    }
}
