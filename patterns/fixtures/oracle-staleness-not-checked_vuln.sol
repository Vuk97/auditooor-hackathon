// SPDX-License-Identifier: MIT
// Fixture: oracle-staleness-not-checked — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
    function decimals() external view returns (uint8);
}

contract LendingVuln {
    // precondition: state var named like a Chainlink feed reference.
    AggregatorV3Interface public priceFeed;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address feed) {
        priceFeed = AggregatorV3Interface(feed);
    }

    // VULN: reads latestRoundData() but ignores updatedAt AND answeredInRound.
    // If the Chainlink feed freezes, `answer` is arbitrarily old but still
    // consumed by borrow() as if live.
    function _getPrice() internal view returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        require(answer > 0, "neg");
        return uint256(answer);
    }

    function borrow(uint256 amount) external {
        uint256 price = _getPrice();
        uint256 collateralUsd = collateral[msg.sender] * price;
        require(collateralUsd >= (debt[msg.sender] + amount) * 15e7 / 1e8, "undercollateralised");
        debt[msg.sender] += amount;
    }
}
