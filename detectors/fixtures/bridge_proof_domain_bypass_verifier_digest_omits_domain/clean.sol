// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeProofDomainBypassVerifierDigestOmitsDomainClean {
    bytes public constant FIAT_SHAMIR_DOMAIN_ID = bytes("BRIDGE-FS-v1");

    struct ValidatorSet {
        bytes32 root;
        uint256 id;
        uint256 length;
    }

    ValidatorSet public currentSet;
    uint32 public immutable remoteDomain;
    uint32 public immutable localDomain;
    bytes32 public routeId;

    constructor(uint32 remoteDomain_, uint32 localDomain_) {
        remoteDomain = remoteDomain_;
        localDomain = localDomain_;
    }

    function verifyInboundProof(
        uint32 sourceDomain,
        uint32 destinationDomain,
        bytes32 proofRoot,
        bytes32 messageHash,
        bytes32[] calldata proof,
        bytes calldata payload
    ) external view returns (bytes32 verifiedLeaf) {
        require(sourceDomain == remoteDomain, "wrong source");
        require(destinationDomain == localDomain, "wrong destination");
        proof;
        payload;

        verifiedLeaf = keccak256(
            abi.encode(sourceDomain, destinationDomain, routeId, address(this), proofRoot, messageHash)
        );
    }

    function createFiatShamirHash(
        bytes32 commitmentHash,
        bytes32 bitFieldHash
    ) public view returns (bytes32 challenge) {
        challenge = sha256(
            bytes.concat(
                FIAT_SHAMIR_DOMAIN_ID,
                sha256(
                    bytes.concat(
                        commitmentHash,
                        bitFieldHash,
                        currentSet.root,
                        bytes32(currentSet.id),
                        bytes32(currentSet.length)
                    )
                )
            )
        );
    }
}
