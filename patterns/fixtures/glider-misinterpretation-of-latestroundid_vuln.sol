// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAgg {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract FeedVuln {
    IAgg public feed;
    uint80 public latestRoundId;

    function getPrice() external view returns (int256) {
        (uint80 roundId, int256 answer, , , ) = feed.latestRoundData();
        require(roundId >= latestRoundId, "stale");
        return answer;
    }
}
