// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same consumer shape as
/// the vuln fixture, but validates `roundId != 0` AND the canonical
/// `roundId >= answeredInRound` stale-round guard before using the price.
interface IAggregatorV3 {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract ChainlinkRoundIdClean {
    IAggregatorV3 public priceFeed;
    address public oracle;

    constructor(address _feed) {
        priceFeed = IAggregatorV3(_feed);
        oracle = _feed;
    }

    // CLEAN: both non-zero and stale-round guards are present.
    function getPrice() external view returns (int256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) =
            priceFeed.latestRoundData();
        require(roundId != 0, "uninitialized round");
        require(roundId >= answeredInRound, "stale round");
        require(answer > 0, "bad price");
        require(updatedAt > 0, "bad timestamp");
        return answer;
    }
}
