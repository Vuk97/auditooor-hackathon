// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — _owner passed directly to __BoringOwnableV2_init, skipping msg.sender.
// Source: pendle-finance/pendle-core-v2-public@3743c6a

abstract contract BoringOwnable {
    address public owner;
    function __BoringOwnableV2_init(address _owner) internal {
        owner = _owner;
    }
    function transferOwnership(address newOwner, bool direct, bool renounce) public virtual {
        owner = newOwner;
    }
}

contract LimitRouterBase is BoringOwnable {
    address public feeRecipient;
    bool private _initialized;

    // VULNERABLE: passes _owner directly to __init — deployer (msg.sender) never gets ownership
    function initialize(address _feeRecipient, address _owner) external {
        require(!_initialized, "Already initialized");
        _initialized = true;
        __BoringOwnableV2_init(_owner); // BUG: should be msg.sender
        feeRecipient = _feeRecipient;
        // transferOwnership never reached with correct semantics
    }
}
