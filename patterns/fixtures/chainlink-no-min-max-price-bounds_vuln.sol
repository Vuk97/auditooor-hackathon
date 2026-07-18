// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// chainlink-no-min-max-price-bounds detector. DO NOT DEPLOY.
///
/// Reads a Chainlink aggregator via latestRoundData() and trusts the
/// returned answer without comparing it against the aggregator's
/// minAnswer / maxAnswer. During a depeg the feed clamps at minAnswer
/// and this contract will keep valuing collateral at the floor.
interface IAggregatorV3 {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract ChainlinkConsumerVuln {
    IAggregatorV3 public priceFeed;

    constructor(address _feed) {
        priceFeed = IAggregatorV3(_feed);
    }

    // VULN: no minAnswer / maxAnswer bound check — clamped feed is accepted.
    function getCollateralValue(uint256 units) external view returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        require(answer > 0, "bad price");
        return units * uint256(answer);
    }
}
