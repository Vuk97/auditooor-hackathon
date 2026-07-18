// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
    function priceCumulativeLast() external view returns (uint256);
}

contract LpVirtualPriceUsedAsOracleClean {
    ICurvePool public pool;
    uint256 public lastCumulative;
    uint256 public lastTs;
    uint256 public lastTwap;

    function setPool(address p) external { pool = ICurvePool(p); }

    // Cleaner: explicit TWAP via priceCumulative delta.
    function getPrice() external view returns (uint256) {
        uint256 cumNow = pool.priceCumulativeLast();
        uint256 twap = (cumNow - lastCumulative) / (block.timestamp - lastTs + 1);
        return twap;
    }
}
