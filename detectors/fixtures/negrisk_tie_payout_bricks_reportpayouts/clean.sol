// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NegRiskUmaCtfAdapterClean {
    error InvalidOOPrice();
    error TieUnsupported();

    bool public immutable isNegRisk;

    constructor(bool _isNegRisk) {
        isNegRisk = _isNegRisk;
    }

    function _constructPayouts(int256 price) external view returns (uint256[] memory) {
        uint256[] memory payouts = new uint256[](2);
        if (price != 0 && price != 0.5 ether && price != 1 ether) revert InvalidOOPrice();

        if (price == 0) {
            payouts[0] = 0;
            payouts[1] = 1;
        } else if (price == 0.5 ether) {
            if (isNegRisk) revert TieUnsupported();
            payouts[0] = 1;
            payouts[1] = 1;
        } else {
            payouts[0] = 1;
            payouts[1] = 0;
        }

        return payouts;
    }
}
