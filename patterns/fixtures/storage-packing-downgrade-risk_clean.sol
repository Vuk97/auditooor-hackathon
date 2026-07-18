// SPDX-License-Identifier: MIT
// Fixture: storage-packing-downgrade-risk — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

contract CleanPack {
    uint256 public slotA;

    // CLEAN: bound `remaining` to type(uint8).max BEFORE the assembly pack.
    // A caller supplying > 255 reverts explicitly instead of silently
    // truncating.
    function setRemaining(uint256 remaining, uint256 counter) external {
        require(remaining <= type(uint8).max, "remaining overflow");
        uint256 packed;
        assembly {
            packed := or(shl(8, remaining), counter)
        }
        slotA = packed;
    }

    // CLEAN variant: explicit numeric bound on a wider field (uint16).
    function rebalance(uint256 x) external {
        require(x <= 65535, "x overflow");
        uint256 v;
        assembly {
            v := shr(16, x)
        }
        slotA = v;
    }
}
