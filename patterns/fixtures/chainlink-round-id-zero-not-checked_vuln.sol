// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// chainlink-round-id-zero-not-checked detector. DO NOT DEPLOY.
///
/// Destructures the 5-tuple from Chainlink latestRoundData() but never
/// asserts that `roundId` is non-zero or that `roundId >= answeredInRound`.
/// A freshly migrated or uninitialized aggregator can report roundId == 0
/// and this consumer will use the accompanying `answer` as if it were the
/// current market price.
interface IAggregatorV3 {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract ChainlinkRoundIdVuln {
    IAggregatorV3 public priceFeed;
    address public oracle;

    constructor(address _feed) {
        priceFeed = IAggregatorV3(_feed);
        oracle = _feed;
    }

    // VULN: roundId is destructured but never validated.
    function getPrice() external view returns (int256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) =
            priceFeed.latestRoundData();
        require(answer > 0, "bad price");
        require(updatedAt > 0, "bad timestamp");
        // Silences unused-variable warning without actually validating.
        roundId;
        answeredInRound;
        return answer;
    }
}
