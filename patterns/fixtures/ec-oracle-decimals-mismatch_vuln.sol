// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

// VULN: Chainlink 8-dec price multiplied by 18-dec token amount without scaling
// Loss ref: Compound oracle decimals misconfiguration, 2020; Angle Protocol, 2023
// https://compound.finance/governance/proposals/47
contract OracleDecimalsVuln {
    AggregatorV3Interface public feed; // 8-decimal price feed

    constructor(address _feed) { feed = AggregatorV3Interface(_feed); }

    // VULN: price has 8 decimals, amount has 18 decimals — result is off by 1e10
    function getCollateralValue(uint256 tokenAmount) external view returns (uint256) {
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0, "bad price");
        // WRONG: 1e8 * 1e18 = 1e26, but intended value is 1e18 (18 decimals)
        return tokenAmount * uint256(price); // missing /1e8 normalization
    }
}
