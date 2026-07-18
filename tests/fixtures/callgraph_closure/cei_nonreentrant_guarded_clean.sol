// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (c): ext-call-then-write but the fn carries a nonReentrant guard ->
// the ordering is safe; intra_cei_suspect=FALSE (never-false-positive).
contract CeiNonReentrantGuardedClean {
    mapping(address => uint256) public balances;
    uint256 private _locked;

    modifier nonReentrant() {
        require(_locked == 0, "reentrant");
        _locked = 1;
        _;
        _locked = 0;
    }

    function withdraw() external nonReentrant {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;   // AFTER the call, but the guard makes it safe
    }
}
