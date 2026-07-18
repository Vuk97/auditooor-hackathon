// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4-4): withdraw() calls an INTERNAL helper `_pureHelper()` that does NO
// external call (pure accounting), THEN does a state-write. The internal call is
// NOT ext-bearing, so the transitive recognition does NOT flip seen_ext -> NOT
// flagged. This pins that the transitive marker only fires when the closure truly
// reaches an external call (never-false-positive on a benign internal call).
contract InterprocCeiInternalNoExtClean {
    mapping(address => uint256) public balances;
    uint256 public total;

    function withdraw() external {
        uint256 amt = balances[msg.sender];
        _pureHelper(amt);             // INTERNAL call with NO external call inside
        balances[msg.sender] = 0;     // state-write, but no external call ever preceded it
    }

    function _pureHelper(uint256 amt) internal {
        total = total - amt;          // pure state accounting, no external call
    }
}
