// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — init with msg.sender, then transferOwnership to _owner.
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

    // FIXED: msg.sender gets initial ownership for setup; then transferred to _owner
    function initialize(address _feeRecipient, address _owner) external {
        require(!_initialized, "Already initialized");
        _initialized = true;
        __BoringOwnableV2_init(msg.sender); // deployer gets temporary ownership
        feeRecipient = _feeRecipient;
        transferOwnership(_owner, true, false); // hand off to intended owner
    }
}
