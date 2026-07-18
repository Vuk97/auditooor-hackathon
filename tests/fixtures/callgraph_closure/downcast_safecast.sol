// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (c): the SAFE form - the narrowing goes through a SafeCast.toUint64()
// wrapper that require-checks the bound before casting (reverts on overflow). At
// the CALL SITE this is a LibraryCall, NOT a TypeConversion, so the oracle must
// NOT flag it (never-false-positive). The library's own internal uint64(value)
// cast is suppressed because the enclosing fn is a SafeCast wrapper body.
library SafeCast {
    function toUint64(uint256 value) internal pure returns (uint64) {
        require(value <= type(uint64).max, "SafeCast: overflow");
        return uint64(value);
    }
}

contract DowncastSafeCast {
    using SafeCast for uint256;
    mapping(address => uint64) public credited;

    // SAFE: SafeCast.toUint64(amount) - a LibraryCall, not a raw cast -> NOT flagged.
    function pay(uint256 amount) external {
        credited[msg.sender] = SafeCast.toUint64(amount);
    }
}
