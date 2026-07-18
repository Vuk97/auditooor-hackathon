// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Gap W1 CLEAN fixture: the child override KEEPS an equivalent caller-identity
// guard - it re-adds an inline require(msg.sender == owner) instead of the base
// modifier. has_guard_in_closure(Derived.setConfig) is True, so this is NOT a
// drop. override_dropped_guards(Derived) must NOT flag.
contract BaseKeepGuard {
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

contract Derived is BaseKeepGuard {
    // Override re-adds an EQUIVALENT inline caller-identity guard -> not a drop.
    function setConfig(uint256 v) external override {
        require(msg.sender == owner, "not owner");
        config = v;
    }
}
