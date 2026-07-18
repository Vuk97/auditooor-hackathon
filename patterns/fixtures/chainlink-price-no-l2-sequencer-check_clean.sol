// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but consults the Chainlink L2 Sequencer Uptime Feed before
/// trusting the price, and enforces a grace period after sequencer restart.
interface IAggregatorV3 {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract L2PriceConsumerClean {
    IAggregatorV3 public priceFeed;
    IAggregatorV3 public sequencerUptimeFeed;
    uint256 public constant GRACE_PERIOD_TIME = 3600;

    constructor(address _feed, address _uptimeFeed) {
        priceFeed = IAggregatorV3(_feed);
        sequencerUptimeFeed = IAggregatorV3(_uptimeFeed);
    }

    // CLEAN: consults the L2 sequencer uptime feed and enforces a
    // gracePeriod window before trusting any price.
    function getCollateralValue(uint256 units) external view returns (uint256) {
        (, int256 sequencerAnswer, uint256 startedAt, , ) =
            sequencerUptimeFeed.latestRoundData();
        require(sequencerAnswer == 0, "SequencerDown");
        require(
            block.timestamp - startedAt > GRACE_PERIOD_TIME,
            "GracePeriodNotOver"
        );

        (, int256 answer, , , ) = priceFeed.latestRoundData();
        require(answer > 0, "bad price");
        return units * uint256(answer);
    }
}
