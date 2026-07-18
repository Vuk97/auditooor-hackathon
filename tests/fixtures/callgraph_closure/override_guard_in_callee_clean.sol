// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Gap W1 CLEAN fixture: the child override moves the guard into a FORWARD
// CALLEE (`_assertOwner()`), reachable via has_guard_in_closure's forward
// closure. The guard is not dropped, just relocated one hop. The override
// verdict is True, so override_dropped_guards(Derived) must NOT flag.
contract BaseCalleeGuard {
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

contract Derived is BaseCalleeGuard {
    function _assertOwner() internal view {
        require(msg.sender == owner, "not owner");
    }

    // Override moves the guard into a forward callee -> caught by the closure,
    // NOT a drop.
    function setConfig(uint256 v) external override {
        _assertOwner();
        config = v;
    }
}
