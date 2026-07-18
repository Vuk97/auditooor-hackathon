// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RestakingSlashFinalizeAfterOperatorUnregisterPositive {
    struct QueuedSlashing {
        address operator;
        address dss;
        uint256 requestedAmount;
    }

    mapping(bytes32 => QueuedSlashing) internal queuedSlashings;
    mapping(address => mapping(address => uint256)) internal earmarkedStakes;
    mapping(address => mapping(address => bool)) internal operatorRegistered;

    event SlashFinalized(address indexed operator, address indexed dss, uint256 amount);

    function finalizeSlashing(bytes32 slashId) external {
        QueuedSlashing storage queuedSlashing = queuedSlashings[slashId];
        uint256 slashAmount = earmarkedStakes[queuedSlashing.operator][queuedSlashing.dss];

        _moveToSlashStore(queuedSlashing.operator, queuedSlashing.dss, slashAmount);
        delete queuedSlashings[slashId];
    }

    function _moveToSlashStore(address operator, address dss, uint256 amount) internal {
        emit SlashFinalized(operator, dss, amount);
    }
}
