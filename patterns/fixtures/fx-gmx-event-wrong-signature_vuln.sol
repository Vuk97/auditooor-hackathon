// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — signalSetMinter emits SignalSetHandler (wrong event).
// Source: GMX-io/gmx-contracts@276a083

contract Timelock {
    event SignalSetHandler(address target, address handler, bool isActive, bytes32 action);

    mapping(bytes32 => uint256) private _pendingActions;

    function _setPendingAction(bytes32 action) internal {
        _pendingActions[action] = block.timestamp;
    }

    // VULNERABLE: emits SignalSetHandler instead of a dedicated SignalSetMinter event
    function signalSetMinter(address _target, address _minter, bool _isActive) external {
        bytes32 action = keccak256(abi.encodePacked("setMinter", _target, _minter, _isActive));
        _setPendingAction(action);
        // BUG: wrong event emitted — monitoring for SignalSetMinter will miss this
        emit SignalSetHandler(_target, _minter, _isActive, action);
    }
}
