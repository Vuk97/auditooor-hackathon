// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
}

contract LpVirtualPriceUsedAsOracleVuln {
    ICurvePool public pool;

    function setPool(address p) external { pool = ICurvePool(p); }

    function getPrice() external view returns (uint256) {
        // VULN: spot virtual price used as oracle input.
        return pool.get_virtual_price();
    }
}
