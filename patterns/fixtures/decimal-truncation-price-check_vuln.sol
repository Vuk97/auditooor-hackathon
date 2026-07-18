// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PriceCheckVuln {
    uint256 public fromPrice;
    uint256 public toPrice;
    uint256 public priceChangeLimit = 105;

    /// VULN: ratio via integer division — truncates to 0/1 near equal prices.
    function checkRatio() external view returns (bool) {
        uint256 r = fromPrice / toPrice;
        return r <= priceChangeLimit;
    }
}
