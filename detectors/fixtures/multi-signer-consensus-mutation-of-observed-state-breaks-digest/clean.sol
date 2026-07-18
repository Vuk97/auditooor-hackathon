// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ConsensusDigestMutationClean {
    enum ConsistencyLevel {
        Custom,
        Safe,
        Finalized
    }

    struct MessagePublication {
        bytes32 emitter;
        bytes payload;
        ConsistencyLevel ConsistencyLevel;
    }

    struct PendingObservation {
        MessagePublication message;
        ConsistencyLevel effectiveCL;
        bytes32 vaaDigest;
    }

    mapping(bytes32 => uint8) internal remoteConfig;

    function cclHandleMessage(
        PendingObservation memory pe,
        bytes32 observationId
    ) public returns (bytes32) {
        pe.effectiveCL = readContract(pe.message.emitter);
        pe.vaaDigest = digest(pe.message, observationId);
        return pe.vaaDigest;
    }

    function readContract(bytes32 emitter) internal view returns (ConsistencyLevel) {
        return remoteConfig[emitter] == 1
            ? ConsistencyLevel.Safe
            : ConsistencyLevel.Finalized;
    }

    function digest(
        MessagePublication memory message,
        bytes32 observationId
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                observationId,
                message.emitter,
                message.payload,
                message.ConsistencyLevel
            )
        );
    }
}
