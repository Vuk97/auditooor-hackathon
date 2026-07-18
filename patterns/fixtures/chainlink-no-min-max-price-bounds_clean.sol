// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but reads the aggregator's minAnswer / maxAnswer and rejects
/// prices that touch either boundary. A clamped (depegged) feed therefore
/// reverts rather than silently being trusted as the true market price.
interface IAggregatorV3 {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
    function minAnswer() external view returns (int192);
    function maxAnswer() external view returns (int192);
}

contract ChainlinkConsumerClean {
    IAggregatorV3 public priceFeed;

    constructor(address _feed) {
        priceFeed = IAggregatorV3(_feed);
    }

    // CLEAN: enforces price > minAnswer && price < maxAnswer.
    function getCollateralValue(uint256 units) external view returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        int192 minP = priceFeed.minAnswer();
        int192 maxP = priceFeed.maxAnswer();
        require(answer > int256(minP), "price at or below minAnswer");
        require(answer < int256(maxP), "price at or above maxAnswer");
        return units * uint256(answer);
    }
}
