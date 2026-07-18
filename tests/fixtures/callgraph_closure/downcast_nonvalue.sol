// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (e): a NARROWING cast uint256 -> uint8 on a NON-VALUE operand `flagId`
// (not amount/balance/shares/... and explicitly an id/flag). The cast IS lossy,
// but the operand is not a unit of protocol value, so the oracle must NOT flag it
// (never-false-positive on a non-economic downcast - we only LEAD on value movers).
contract DowncastNonValue {
    mapping(uint8 => bool) public flags;

    // NOT flagged: the operand is a flag identifier, not a value mover.
    function setFlag(uint256 flagId) external {
        uint8 narrowedId = uint8(flagId);
        flags[narrowedId] = true;
    }
}
