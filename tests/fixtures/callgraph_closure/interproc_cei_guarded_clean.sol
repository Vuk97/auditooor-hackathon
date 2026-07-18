// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4-3): same TRANSITIVE shape as W4-1 (withdraw -> _doCall ext -> write)
// but withdraw() carries a nonReentrant guard -> the ordering is safe;
// intra_cei_suspect=FALSE (guard suppression intact, even for the transitive path).
contract InterprocCeiGuardedClean {
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
        _doCall(amt);                 // INTERNAL call that transitively reaches out
        balances[msg.sender] = 0;     // AFTER the transitive call, but the guard makes it safe
    }

    function _doCall(uint256 amt) internal {
        (bool ok, ) = msg.sender.call{value: amt}("");  // the genuine external call
        require(ok, "send failed");
    }
}
