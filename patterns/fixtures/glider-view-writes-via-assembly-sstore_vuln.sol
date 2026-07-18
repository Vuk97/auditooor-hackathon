// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OracleVuln {
    uint256 public cachedPrice;

    /// VULN: declared view but sstores via assembly.
    function getPrice() external view returns (uint256 price) {
        price = 1234;
        assembly {
            sstore(cachedPrice.slot, price)
        }
    }
}
