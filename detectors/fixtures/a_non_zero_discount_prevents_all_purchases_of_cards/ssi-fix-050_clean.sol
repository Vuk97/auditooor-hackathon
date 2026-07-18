// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DiscountAllocationClean {
    uint256 internal discount;
    uint256 internal discountedTotal;

    function getAllocations(uint256 newDiscount) external returns (uint256 vaultPercentage) {
        require(discount + newDiscount <= 10_000, "discount cap");
        discount = newDiscount;
        discountedTotal = 10_000 - newDiscount;
        vaultPercentage = discountedTotal;
    }
}
