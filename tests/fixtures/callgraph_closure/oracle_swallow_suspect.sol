// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceFeed {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

/// Oracle try/catch where the catch SWALLOWS the failure: on a feed revert the
/// function keeps the STALE `price` and proceeds to write the economic
/// `collateralValue` from it. -> FLAGGED (a swallowing oracle try/catch). The
/// economic write also makes this a seedable DefUsePath sink for the slice.
contract OracleSwallow {
    IPriceFeed public feed;
    int256 public price;
    uint256 public collateralValue;

    function refresh(uint256 qty) external {
        try feed.latestRoundData() returns (
            uint80,
            int256 p,
            uint256,
            uint256,
            uint80
        ) {
            price = p;
        } catch {
            // swallow: keep the stale price, no revert / no propagate
        }
        // value-moving logic uses the (possibly stale) price after the try:
        // write the economic collateralValue from the stale price.
        collateralValue = uint256(price) * qty;
    }
}
