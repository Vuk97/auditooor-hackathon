// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOptimismPortal {
    function finalizeWithdrawalTransaction(bytes calldata withdrawalTx) external;
}

interface IFaultDisputeGame {
    function status() external view returns (uint8);
    function resolvedAt() external view returns (uint256);
}

contract OptimismWithdrawalFinalizeRaceWindowCleanFixture {
    uint8 internal constant DEFENDER_WINS = 2;

    struct WithdrawalProof {
        uint256 provenAt;
        IFaultDisputeGame faultDisputeGame;
    }

    IOptimismPortal public immutable optimismPortal;
    uint256 public immutable proofMaturityDelaySeconds;
    uint256 public immutable disputeGameFinalityDelaySeconds;
    mapping(bytes32 => WithdrawalProof) public provenWithdrawals;
    mapping(bytes32 => bool) public finalizedWithdrawals;

    constructor(
        IOptimismPortal portal,
        uint256 maturityDelaySeconds,
        uint256 finalityDelaySeconds
    ) {
        optimismPortal = portal;
        proofMaturityDelaySeconds = maturityDelaySeconds;
        disputeGameFinalityDelaySeconds = finalityDelaySeconds;
    }

    function proveWithdrawal(
        bytes32 withdrawalHash,
        IFaultDisputeGame faultDisputeGame
    ) external {
        provenWithdrawals[withdrawalHash] = WithdrawalProof({
            provenAt: block.timestamp,
            faultDisputeGame: faultDisputeGame
        });
    }

    function finalizeWithdrawal(
        bytes32 withdrawalHash,
        bytes calldata withdrawalTx
    ) external {
        WithdrawalProof memory proof = provenWithdrawals[withdrawalHash];
        require(proof.provenAt != 0, "not proven");
        require(
            block.timestamp >= proof.provenAt + proofMaturityDelaySeconds,
            "proof immature"
        );
        require(proof.faultDisputeGame.status() == DEFENDER_WINS, "bad game");
        require(
            block.timestamp
                >= proof.faultDisputeGame.resolvedAt()
                    + disputeGameFinalityDelaySeconds,
            "game not final"
        );

        finalizedWithdrawals[withdrawalHash] = true;
        optimismPortal.finalizeWithdrawalTransaction(withdrawalTx);
    }
}
