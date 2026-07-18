// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

// VULN: spot price from getReserves() used as collateral oracle
// Loss ref: Harvest Finance ~$34M, Oct 2020; Cheese Bank ~$3.3M, Nov 2020
// https://rekt.news/harvest-finance-rekt/
contract SpotPriceLendingVuln {
    IUniswapV2Pair public pair;
    mapping(address => uint256) public collateral; // in tokenA
    mapping(address => uint256) public debt;       // in USDC

    constructor(address _pair) { pair = IUniswapV2Pair(_pair); }

    // VULN: uses instantaneous AMM reserves as price oracle — flashloan manipulable
    function borrow(uint256 borrowAmount) external {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        // price = reserve1/reserve0 — manipulable in single tx via flashloan
        uint256 price = uint256(reserve1) * 1e18 / uint256(reserve0);
        uint256 collateralValue = collateral[msg.sender] * price / 1e18;
        require(collateralValue >= borrowAmount * 150 / 100, "undercollateralized");
        debt[msg.sender] += borrowAmount;
    }
}
