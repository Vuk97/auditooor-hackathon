// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RestakingSlashFinalizeAfterOperatorUnregisterClean {
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
        address operator = queuedSlashing.operator;
        require(
            isOperatorRegisteredToDSS(operator, queuedSlashing.dss),
            "operator not registered"
        );

        uint256 slashAmount = earmarkedStakes[operator][queuedSlashing.dss];
        _moveToSlashStore(operator, queuedSlashing.dss, slashAmount);
        delete queuedSlashings[slashId];
    }

    function isOperatorRegisteredToDSS(address operator, address dss) internal view returns (bool) {
        return operatorRegistered[operator][dss];
    }

    function _moveToSlashStore(address operator, address dss, uint256 amount) internal {
        emit SlashFinalized(operator, dss, amount);
    }
}
