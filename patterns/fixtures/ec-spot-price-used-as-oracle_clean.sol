// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256 updatedAt, uint80
    );
}

// CLEAN: uses Chainlink TWAP-equivalent feed, not spot AMM reserves
contract SpotPriceLendingClean {
    AggregatorV3Interface public oracle;
    uint256 public constant MAX_STALENESS = 3600;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _oracle) { oracle = AggregatorV3Interface(_oracle); }

    // CLEAN: manipulation-resistant Chainlink price feed
    function borrow(uint256 borrowAmount) external {
        (, int256 answer,, uint256 updatedAt,) = oracle.latestRoundData();
        require(answer > 0, "bad price");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale");
        uint256 price = uint256(answer) * 1e10; // normalize 8dec → 18dec
        uint256 collateralValue = collateral[msg.sender] * price / 1e18;
        require(collateralValue >= borrowAmount * 150 / 100, "undercollateralized");
        debt[msg.sender] += borrowAmount;
    }
}
