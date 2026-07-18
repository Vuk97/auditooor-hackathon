// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (c): hollow inherited modifier.
// `Child.privileged()` carries the inherited `whenAuthorized` modifier in its
// HEADER, but the modifier BODY omits any real msg.sender check (it only does
// `_;`). A header-only check sees the modifier name and FALSE-NEGATIVE assumes
// it is guarded. has_guard_in_closure(privileged) folds the modifier BODY and
// must return False (genuinely unguarded).
contract BaseHollow {
    // Looks like an auth modifier by name, but the body is hollow.
    modifier whenAuthorized() {
        _;
    }
}

contract Child is BaseHollow {
    uint256 public x;

    function privileged() external whenAuthorized {
        x += 1;
    }
}
