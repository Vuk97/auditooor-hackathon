// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Gap W1 FLAGGED fixture: a legacy-style `onlyOwner` modifier on the base is
// DROPPED by the child override. The base `setConfig` enforces
// require(msg.sender == owner) via its modifier body; the child override omits
// the modifier entirely, so the dispatched (leaf) implementation is UNGUARDED.
// override_dropped_guards(Derived) must FLAG Derived.setConfig.
contract BaseGuardedOnlyOwner {
    address public owner;
    uint256 public config;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setConfig(uint256 v) external virtual onlyOwner {
        config = v;
    }
}

contract Derived is BaseGuardedOnlyOwner {
    // Override DROPS the onlyOwner guard - now anyone can set config.
    function setConfig(uint256 v) external override {
        config = v;
    }
}
