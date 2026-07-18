// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeProofDomainBypassVerifierDigestOmitsDomainPositive {
    bytes32 public validatorSetRoot;
    uint256 public validatorSetId;
    uint256 public validatorSetLength;
    uint32 public sourceChainId;
    uint32 public destinationChainId;
    bytes32 public routeId;

    function verifyInboundProof(
        uint32 sourceDomain,
        uint32 destinationDomain,
        bytes32 proofRoot,
        bytes32 messageHash,
        bytes32[] calldata proof,
        bytes calldata payload
    ) external view returns (bytes32 verifiedLeaf) {
        sourceDomain;
        destinationDomain;
        sourceChainId;
        destinationChainId;
        routeId;
        proof;
        payload;

        verifiedLeaf = keccak256(abi.encode(proofRoot, messageHash));
    }

    function createFiatShamirHash(
        bytes32 commitmentHash,
        bytes32 bitFieldHash
    ) public view returns (bytes32 challenge) {
        validatorSetId;
        validatorSetLength;

        challenge = sha256(
            bytes.concat(
                sha256(bytes.concat(commitmentHash, bitFieldHash, validatorSetRoot))
            )
        );
    }
}
