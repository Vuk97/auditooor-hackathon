// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4 FP-fix #4, never-MISS): an INTERNAL helper calls an external function
// of UNKNOWN / non-view mutability (declared without `view`/`pure` - it could write
// state and reenter), THEN the caller writes state. The CEI-scoped predicate is
// CONSERVATIVE: only a POSITIVELY view/pure target is excluded, so this UNKNOWN /
// state-mutating target STILL counts as a reentrant external call -> STILL FLAGGED.
// Pins that the FP fix never silences a real CEI by mis-treating unknown mutability.
interface IThing {
    // no `view`/`pure`: mutability is unknown/mutating -> must be treated as reentrant
    function mystery(uint256 x) external returns (uint256);
}

contract InterprocCeiUnknownMutabilityViaHelperSuspect {
    IThing public thing;
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amt = balances[msg.sender];
        _doThing(amt);                // INTERNAL helper that reaches an UNKNOWN-mutability external call
        balances[msg.sender] = 0;     // state-write AFTER the (possibly reentrant) external call -> FLAGGED
    }

    function _doThing(uint256 amt) internal {
        thing.mystery(amt);           // external call, mutability NOT proven view/pure -> reentrant-relevant
    }
}
