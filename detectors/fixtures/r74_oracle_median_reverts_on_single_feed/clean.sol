pragma solidity ^0.8.20;

interface MedianFeed {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

contract OracleMedianSingleFeedClean {
    MedianFeed[] public priceFeeds;
    uint256 public minSuccessfulFeeds;

    constructor(MedianFeed[] memory feeds, uint256 minSuccess) {
        for (uint256 i = 0; i < feeds.length; ++i) {
            priceFeeds.push(feeds[i]);
        }
        minSuccessfulFeeds = minSuccess;
    }

    function medianPrice() public view returns (int256 median) {
        int256[] memory answers = new int256[](priceFeeds.length);
        uint256 successes;

        for (uint256 i = 0; i < priceFeeds.length; ++i) {
            try priceFeeds[i].latestRoundData() returns (
                uint80,
                int256 answer,
                uint256,
                uint256,
                uint80
            ) {
                answers[successes] = answer;
                successes++;
            } catch {
                continue;
            }
        }

        require(successes >= minSuccessfulFeeds, "insufficient live feeds");
        median = answers[successes / 2];
    }
}
