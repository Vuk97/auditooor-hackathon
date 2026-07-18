// SPDX-License-Identifier: MIT
// Fixture: storage-packing-downgrade-risk — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract VulnPack {
    // Packed layout: high byte = remaining (uint8), rest = counter (uint248).
    uint256 public slotA;

    // VULN: inline-assembly pack uses shl(8, remaining) with no bound on
    // `remaining`. Caller-supplied values > 255 silently truncate modulo 256
    // when packed, corrupting downstream bookkeeping.
    function setRemaining(uint256 remaining, uint256 counter) external {
        uint256 packed;
        assembly {
            packed := or(shl(8, remaining), counter)
        }
        slotA = packed;
    }

    // VULN variant: shr (right shift) rebalance, still no bound on input.
    function rebalance(uint256 x) external {
        uint256 v;
        assembly {
            v := shr(16, x)
        }
        slotA = v;
    }
}
