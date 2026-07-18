// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (d): a WIDENING cast uint64 -> uint256 on a value-moving `amount`. A
// widening conversion is LOSSLESS (cast_is_lossy == "lossless"), so the oracle
// must NOT flag it (never-false-positive on a safe widen).
contract DowncastWidening {
    mapping(address => uint256) public credited;

    // SAFE: widening uint64 -> uint256 on a value operand -> NOT flagged.
    function pay(uint64 amount) external {
        uint256 widened = uint256(amount);
        credited[msg.sender] = widened;
    }
}
