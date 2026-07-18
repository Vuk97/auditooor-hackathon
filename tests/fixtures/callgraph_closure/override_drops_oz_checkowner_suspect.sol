// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Gap W1 FLAGGED fixture: OZ-style onlyOwner -> _checkOwner indirection on the
// base is DROPPED by the child override. The base modifier body has no direct
// msg.sender read; it calls _checkOwner() (recognized authz helper). The child
// override omits the modifier, so the dispatched implementation is UNGUARDED.
// override_dropped_guards(Derived) must FLAG Derived.transferTreasury.
contract OzOwnableBase {
    address private _owner;
    address public treasury;

    constructor() {
        _owner = msg.sender;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    // OZ-style: the revert lives inside _checkOwner, not in the modifier node.
    function _checkOwner() internal view {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function transferTreasury(address to) external virtual onlyOwner {
        treasury = to;
    }
}

contract Derived is OzOwnableBase {
    // Override DROPS the onlyOwner -> _checkOwner guard.
    function transferTreasury(address to) external override {
        treasury = to;
    }
}
