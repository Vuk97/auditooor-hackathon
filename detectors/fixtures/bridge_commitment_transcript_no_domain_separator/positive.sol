// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: Bridge finality commitment transcript uses double-sha256(bytes.concat(...))
// over (commitmentHash, messageHash, validatorRoot) but has NO domain separator constant
// in the outer sha256 preimage. Transcript can be replayed across validator-set contexts.

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

contract BeefyCommitmentTranscriptVuln {
    uint256 public requiredSignatures = 5;

    // VULN: sha256(bytes.concat(sha256(bytes.concat(commitmentHash, messageHash, validatorRoot))))
    // No domain constant in outer layer; no vset.id/vset.length in inner layer.
    function _computeTranscriptHash(
        bytes32 commitmentHash,
        bytes32 messageHash,
        bytes32 validatorRoot
    ) internal pure returns (bytes32) {
        return sha256(
            bytes.concat(sha256(bytes.concat(commitmentHash, messageHash, validatorRoot)))
        );
    }

    function sampleValidators(
        bytes32 commitmentHash,
        uint256[] calldata bitfield,
        uint256 validatorSetLength,
        bytes32 validatorRoot
    ) external view returns (uint256[] memory) {
        bytes32 msgHash = keccak256(abi.encodePacked(bitfield));
        bytes32 transcript = _computeTranscriptHash(commitmentHash, msgHash, validatorRoot);
        return Bitfield.subsample(uint256(transcript), bitfield, validatorSetLength, requiredSignatures);
    }
}
