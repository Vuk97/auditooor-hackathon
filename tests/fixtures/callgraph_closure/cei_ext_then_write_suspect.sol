// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (a): SAME-FN CEI VIOLATION - an external call THEN a state-write within
// ONE function, with NO reentrancy guard (intra_cei_suspect=TRUE). The classic
// reentrancy shape the cross-fn closure oracle misses (it sees call EDGES, not
// this fn's own statement ORDER).
contract CeiExtThenWriteSuspect {
    mapping(address => uint256) public balances;

    // CEI-VIOLATION: external call BEFORE the balance zeroing. // CEI-TARGET
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;   // state-write AFTER the external call
    }
}
