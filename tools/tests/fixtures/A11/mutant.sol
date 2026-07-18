// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAME module as clean.sol but the onlyProxy context-binding guard was DROPPED
// from `setConfig`. The onlyProxy modifier still exists (so the contract is
// still a delegatecall target), but setConfig now TRUSTS the context blindly:
// it writes storage under any caller context. MUST be flagged (needs-fuzz).
contract LogicModule {
    address public immutable __self;
    uint256 public config;

    constructor() {
        __self = address(this);
    }

    modifier onlyProxy() {
        require(address(this) != __self, "only delegatecall");
        _;
    }

    // guard DROPPED -> context-binding trust with no assertion.
    function setConfig(uint256 v) external {
        config = v;
    }
}
