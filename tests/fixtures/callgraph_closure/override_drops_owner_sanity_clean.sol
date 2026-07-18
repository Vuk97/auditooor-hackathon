// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Gap W1 CLEAN fixture (FP regression): the base `update()` is PERMISSIONLESS.
// Its only require is a ZERO-ADDRESS SANITY check `require(owner() != address(0))`
// - it NAMES the `owner` accessor but never compares the accessor against the
// caller (msg.sender / _msgSender()), so it is NOT access control. The child
// override merely omits that sanity require; both base and override are equally
// permissionless. Dropping a non-caller-identity sanity check is NOT an
// access-control drop, so override_dropped_guards(Derived) must NOT flag.
//
// Before the W1 stricter base-guard predicate, the permissive default's
// accessor-name-in-revert signal (3) misread `require(owner() != address(0))` as
// a guard and FALSELY flagged this override as a drop. The stricter predicate
// requires a genuine caller read, so this is now clean.
contract BaseSanityOnly {
    address private _owner;
    uint256 public value;

    constructor() {
        _owner = msg.sender;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    // Zero-address SANITY check, not access control: names owner() but never
    // compares it against the caller. Anyone may call update().
    function update(uint256 v) external virtual {
        require(owner() != address(0), "owner unset");
        value = v;
    }
}

contract Derived is BaseSanityOnly {
    // Override drops the SANITY require. Still permissionless - nothing was
    // access-controlled, so nothing was dropped.
    function update(uint256 v) external override {
        value = v;
    }
}
