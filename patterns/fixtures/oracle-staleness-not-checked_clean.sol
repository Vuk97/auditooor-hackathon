// SPDX-License-Identifier: MIT
// Fixture: oracle-staleness-not-checked — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
    function decimals() external view returns (uint8);
}

contract LendingClean {
    AggregatorV3Interface public priceFeed;
    uint256 public stalenessThreshold = 3600;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address feed) {
        priceFeed = AggregatorV3Interface(feed);
    }

    // CLEAN: validates updatedAt against block.timestamp and enforces
    // answeredInRound >= roundId. Both guard forms are present so the
    // body_not_contains_regex predicate rejects the match.
    function _getPrice() internal view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) =
            priceFeed.latestRoundData();
        require(answer > 0, "neg");
        require(block.timestamp - updatedAt <= stalenessThreshold, "stale");
        require(answeredInRound >= roundId, "stale-round");
        return uint256(answer);
    }

    function borrow(uint256 amount) external {
        uint256 price = _getPrice();
        uint256 collateralUsd = collateral[msg.sender] * price;
        require(collateralUsd >= (debt[msg.sender] + amount) * 15e7 / 1e8, "undercollateralised");
        debt[msg.sender] += amount;
    }
}
