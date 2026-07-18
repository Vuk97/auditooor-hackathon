// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — signalSetMinter emits dedicated SignalSetMinter event.
// Source: GMX-io/gmx-contracts@276a083

contract Timelock {
    event SignalSetHandler(address target, address handler, bool isActive, bytes32 action);
    event SignalSetMinter(address target, address minter, bool isActive, bytes32 action);

    mapping(bytes32 => uint256) private _pendingActions;

    function _setPendingAction(bytes32 action) internal {
        _pendingActions[action] = block.timestamp;
    }

    // FIXED: dedicated SignalSetMinter event for minter changes
    function signalSetMinter(address _target, address _minter, bool _isActive) external {
        bytes32 action = keccak256(abi.encodePacked("setMinter", _target, _minter, _isActive));
        _setPendingAction(action);
        emit SignalSetMinter(_target, _minter, _isActive, action);
    }
}
