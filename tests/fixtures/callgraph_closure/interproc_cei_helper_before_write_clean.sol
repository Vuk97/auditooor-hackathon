// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4-2): CEI-CORRECT ordering across the helper - the state-write happens
// BEFORE the internal helper that transitively reaches out. The transitive ext is
// seen AFTER the write, so there is no write-after-call -> NOT flagged
// (never-false-positive). Same helper as W4-1; only the order differs.
contract InterprocCeiHelperBeforeWriteClean {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;     // EFFECT first (CEI-correct)
        _doCall(amt);                 // INTERNAL call that transitively reaches out, AFTER the write
    }

    function _doCall(uint256 amt) internal {
        (bool ok, ) = msg.sender.call{value: amt}("");  // the genuine external call
        require(ok, "send failed");
    }
}
