// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Stable2LUT1LiquidityExtremePositive {
    struct PriceData {
        uint256 lowPrice;
        uint256 lowReserve0;
        uint256 lowReserve1;
        uint256 highPrice;
        uint256 highReserve0;
        uint256 highReserve1;
        uint256 precision;
    }

    function getRatiosFromPriceLiquidity(uint256 price) public pure returns (PriceData memory) {
        if (price < 0.001083e6) {
            revert("LUT: Invalid price");
        } else {
            return PriceData(
                0.27702e6,
                0,
                9.646293093274934449e18,
                0.001083e6,
                0,
                2000e18,
                1e18
            );
        }
    }
}
