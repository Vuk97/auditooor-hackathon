// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NegRiskUmaCtfAdapterPositive {
    error InvalidOOPrice();

    function _constructPayouts(int256 price) external pure returns (uint256[] memory) {
        uint256[] memory payouts = new uint256[](2);
        if (price != 0 && price != 0.5 ether && price != 1 ether) revert InvalidOOPrice();

        if (price == 0) {
            payouts[0] = 0;
            payouts[1] = 1;
        } else if (price == 0.5 ether) {
            // UNKNOWN: tie / unresolved branch.
            // Note that a tie is not a valid outcome when used with the NegRiskOperator.
            payouts[0] = 1;
            payouts[1] = 1;
        } else {
            payouts[0] = 1;
            payouts[1] = 0;
        }

        return payouts;
    }
}
