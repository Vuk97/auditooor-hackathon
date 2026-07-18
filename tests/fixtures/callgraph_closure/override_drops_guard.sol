// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (f): base guard DROPPED by a child override.
// `BaseGuarded.setConfig` is `onlyOwner`. `Derived` overrides it and OMITS the
// modifier, so the dispatched implementation on `Derived` is UNGUARDED.
// resolve_concrete_impl(Derived, "setConfig(uint256)") must pick the child
// (Derived.setConfig), and has_guard_in_closure on that child must be False,
// whereas on the base it is True.
contract BaseGuarded {
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

contract Derived is BaseGuarded {
    // Override DROPS the onlyOwner guard — now anyone can set config.
    function setConfig(uint256 v) external override {
        config = v;
    }
}
