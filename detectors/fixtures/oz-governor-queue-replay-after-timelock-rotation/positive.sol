// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITimelockController {
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) external;
}

contract OzGovernorQueueReplayAfterTimelockRotationVulnerable {
    event TimelockChange(
        ITimelockController indexed oldTimelock,
        ITimelockController indexed newTimelock
    );

    ITimelockController private _timelock;
    mapping(uint256 => bytes32) private _timelockIds;

    constructor(ITimelockController initialTimelock) {
        _timelock = initialTimelock;
    }

    function hashProposal(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(targets, values, calldatas, descriptionHash)));
    }

    function queue(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata calldatas,
        bytes32 descriptionHash,
        uint256 delay
    ) external returns (uint256 proposalId) {
        proposalId = hashProposal(targets, values, calldatas, descriptionHash);
        bytes32 operationId = bytes32(proposalId);
        _timelockIds[proposalId] = operationId;
        _timelock.scheduleBatch(targets, values, calldatas, bytes32(0), operationId, delay);
    }

    function updateTimelock(ITimelockController newTimelock) public {
        _updateTimelock(newTimelock);
    }

    function _updateTimelock(ITimelockController newTimelock) internal {
        ITimelockController oldTimelock = _timelock;
        _timelock = newTimelock;
        emit TimelockChange(oldTimelock, newTimelock);
    }
}
