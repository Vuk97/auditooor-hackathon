// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — kink_ declared as uint32 so out-of-range values revert at ABI decode.
// Source: euler-xyz/euler-vault-kit@50c5c90

contract IRMLinearKink {
    uint256 public immutable baseRate;
    uint256 public immutable slope1;
    uint256 public immutable slope2;
    uint256 public immutable kink;

    // FIXED: uint32 parameter type causes ABI-level revert on out-of-range input
    constructor(uint256 baseRate_, uint256 slope1_, uint256 slope2_, uint32 kink_) {
        baseRate = baseRate_;
        slope1 = slope1_;
        slope2 = slope2_;
        kink = kink_;
    }
}
