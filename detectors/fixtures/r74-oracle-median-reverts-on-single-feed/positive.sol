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

contract OracleMedianSingleFeedPositive {
    MedianFeed[] public priceFeeds;

    constructor(MedianFeed[] memory feeds) {
        for (uint256 i = 0; i < feeds.length; ++i) {
            priceFeeds.push(feeds[i]);
        }
    }

    function medianPrice() public view returns (int256 median) {
        int256[] memory answers = new int256[](priceFeeds.length);
        for (uint256 i = 0; i < priceFeeds.length; ++i) {
            (, int256 answer, , , ) = priceFeeds[i].latestRoundData();
            answers[i] = answer;
        }

        median = answers[answers.length / 2];
    }
}
