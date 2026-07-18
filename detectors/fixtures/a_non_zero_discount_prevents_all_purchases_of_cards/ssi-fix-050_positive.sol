// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DiscountAllocationPositive {
    uint256 internal discount;
    uint256 internal discountedTotal;

    function getAllocations(uint256 newDiscount) external returns (uint256 vaultPercentage) {
        discount = newDiscount;
        discountedTotal = 10_000 - newDiscount;
        vaultPercentage = discountedTotal;
    }
}
