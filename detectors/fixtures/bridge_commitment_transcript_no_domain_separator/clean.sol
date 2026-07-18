// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: Bridge finality commitment transcript includes a domain separator constant
// and validator-set id/length in the preimage. Domain-bound transcript cannot be
// replayed across different validator-set contexts.

library Bitfield {
    function subsample(
        uint256,
        uint256[] calldata,
        uint256,
        uint256
    ) internal pure returns (uint256[] memory out) {
        out = new uint256[](1);
    }
}

contract BeefyCommitmentTranscriptClean {
    bytes public constant PROTOCOL_DOMAIN_ID = bytes("BEEFY-COMMITMENT-v1");
    uint256 public requiredSignatures = 5;

    // CLEAN: Domain separator constant in outer sha256 + vset.id/vset.length in inner
    function _computeTranscriptHash(
        bytes32 commitmentHash,
        bytes32 messageHash,
        bytes32 validatorRoot,
        uint256 validatorSetId,
        uint256 validatorSetLength
    ) internal pure returns (bytes32) {
        return sha256(
            bytes.concat(
                PROTOCOL_DOMAIN_ID,
                sha256(
                    bytes.concat(
                        commitmentHash,
                        messageHash,
                        validatorRoot,
                        bytes32(validatorSetId),
                        bytes32(validatorSetLength)
                    )
                )
            )
        );
    }

    function sampleValidators(
        bytes32 commitmentHash,
        uint256[] calldata bitfield,
        uint256 validatorSetLength,
        bytes32 validatorRoot,
        uint256 validatorSetId
    ) external view returns (uint256[] memory) {
        bytes32 msgHash = keccak256(abi.encodePacked(bitfield));
        bytes32 transcript = _computeTranscriptHash(commitmentHash, msgHash, validatorRoot, validatorSetId, validatorSetLength);
        return Bitfield.subsample(uint256(transcript), bitfield, validatorSetLength, requiredSignatures);
    }
}
