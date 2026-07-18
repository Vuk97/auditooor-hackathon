// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAgg {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract FeedClean {
    IAgg public feed;
    uint256 public constant HEARTBEAT = 3600;

    function getPrice() external view returns (int256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(answer > 0, "answer");
        require(block.timestamp - updatedAt <= HEARTBEAT, "stale");
        require(answeredInRound >= roundId, "incomplete");
        return answer;
    }
}
