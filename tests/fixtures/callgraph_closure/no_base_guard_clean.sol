// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Gap W1 CLEAN fixture (conservative direction): the BASE itself is UNGUARDED,
// and the child override is also unguarded. There is no guard to drop, so this
// is NOT a drop. A missing base guard must never be treated as a "drop".
// override_dropped_guards(Derived) must NOT flag.
contract BaseUnguarded {
    uint256 public config;

    function setConfig(uint256 v) external virtual {
        config = v;
    }
}

contract Derived is BaseUnguarded {
    // Both base and override are unguarded -> nothing dropped.
    function setConfig(uint256 v) external override {
        config = v;
    }
}
