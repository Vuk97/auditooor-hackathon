// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOptimismPortal {
    function finalizeWithdrawalTransaction(bytes calldata withdrawalTx) external;
}

contract OptimismWithdrawalFinalizeRaceWindowFixture {
    IOptimismPortal public immutable optimismPortal;
    uint256 public immutable finalizationPeriodSeconds;
    mapping(bytes32 => uint256) public provenWithdrawalAt;
    mapping(bytes32 => bool) public finalizedWithdrawals;

    constructor(IOptimismPortal portal, uint256 periodSeconds) {
        optimismPortal = portal;
        finalizationPeriodSeconds = periodSeconds;
    }

    function proveWithdrawal(bytes32 withdrawalHash) external {
        provenWithdrawalAt[withdrawalHash] = block.timestamp;
    }

    function finalizeWithdrawal(
        bytes32 withdrawalHash,
        bytes calldata withdrawalTx
    ) external {
        uint256 provenAt = provenWithdrawalAt[withdrawalHash];
        require(provenAt != 0, "not proven");
        require(
            block.timestamp >= provenAt + finalizationPeriodSeconds,
            "finalization period"
        );

        finalizedWithdrawals[withdrawalHash] = true;
        optimismPortal.finalizeWithdrawalTransaction(withdrawalTx);
    }
}
