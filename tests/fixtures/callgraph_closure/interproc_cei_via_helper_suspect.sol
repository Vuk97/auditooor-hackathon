// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4-1): TRANSITIVE CEI VIOLATION - withdraw() calls an INTERNAL helper
// `_doCall()` that makes the external call, THEN withdraw() does a state-write. The
// caller's node for `_doCall()` is an INTERNAL call (not external), so the direct
// `_node_is_external_call` walk misses it; the transitive-ext recognition flags it
// (intra_cei_suspect=TRUE, transitive=true, via="_doCall"). NO reentrancy guard.
contract InterprocCeiViaHelperSuspect {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amt = balances[msg.sender];
        _doCall(amt);                 // INTERNAL call that transitively reaches out
        balances[msg.sender] = 0;     // state-write AFTER the transitive external call
    }

    function _doCall(uint256 amt) internal {
        (bool ok, ) = msg.sender.call{value: amt}("");  // the genuine external call
        require(ok, "send failed");
    }
}
