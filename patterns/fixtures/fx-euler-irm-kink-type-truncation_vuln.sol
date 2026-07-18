// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — kink_ accepted as uint256 but stored as uint32 (silent truncation).
// Source: euler-xyz/euler-vault-kit@50c5c90

contract IRMLinearKink {
    uint256 public immutable baseRate;
    uint256 public immutable slope1;
    uint256 public immutable slope2;
    // kink is in type(uint32).max scale
    uint256 public immutable kink;

    // VULNERABLE: uint256 parameter silently truncates on assignment to uint32 storage
    constructor(uint256 baseRate_, uint256 slope1_, uint256 slope2_, uint256 kink_) {
        baseRate = baseRate_;
        slope1 = slope1_;
        slope2 = slope2_;
        kink = uint32(kink_); // silent truncation if kink_ > type(uint32).max
    }
}
