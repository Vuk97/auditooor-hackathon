// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// chainlink-price-no-l2-sequencer-check detector. DO NOT DEPLOY.
///
/// Reads a Chainlink price feed on an L2 without first consulting the
/// L2 Sequencer Uptime Feed. During sequencer downtime or the grace
/// period after restart, latestRoundData() returns a stale price that
/// this contract will happily use to value collateral.
interface IAggregatorV3 {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract L2PriceConsumerVuln {
    IAggregatorV3 public priceFeed;

    constructor(address _feed) {
        priceFeed = IAggregatorV3(_feed);
    }

    // VULN: consumes latestRoundData() with zero sequencer-uptime check.
    function getCollateralValue(uint256 units) external view returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        require(answer > 0, "bad price");
        return units * uint256(answer);
    }
}
