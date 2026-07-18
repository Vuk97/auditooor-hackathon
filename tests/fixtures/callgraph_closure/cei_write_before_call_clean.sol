// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (b): CEI-CORRECT - the state-write happens BEFORE the external call
// (checks-effects-interactions). intra_cei_suspect=FALSE (never-false-positive).
contract CeiWriteBeforeCallClean {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;   // EFFECT first
        (bool ok, ) = msg.sender.call{value: amt}("");  // INTERACTION last
        require(ok, "send failed");
    }
}
