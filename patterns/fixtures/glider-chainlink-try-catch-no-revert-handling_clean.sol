// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface AggregatorV3 {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract ChainlinkClean {
    AggregatorV3 public feed;
    int256 public lastPrice;

    function poke() external {
        try feed.latestRoundData() returns (uint80, int256 p, uint256, uint256, uint80) {
            lastPrice = p;
        } catch {
            revert("oracle failed");
        }
    }
}
