// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBeefyClientLike {
    function verifyMMRLeafProof(
        bytes32 leafHash,
        bytes32[] calldata proof,
        uint256 proofOrder
    ) external view returns (bool);
}

library SubstrateMerkleProofLike {
    function computeRoot(
        bytes32 leaf,
        uint256,
        uint256,
        bytes32[] calldata
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode("root", leaf));
    }
}

contract SnowbridgeCommitmentBindingClean {
    bytes1 public constant DIGEST_ITEM_OTHER_SNOWBRIDGE = 0x00;
    bytes1 public constant DIGEST_ITEM_OTHER_SNOWBRIDGE_V2 = 0x01;

    struct DigestItem {
        uint256 kind;
        bytes data;
    }

    struct ParachainHeader {
        bytes32 parentHash;
        uint256 number;
        bytes32 stateRoot;
        bytes32 extrinsicsRoot;
        DigestItem[] digestItems;
    }

    struct HeadProof {
        uint256 pos;
        uint256 width;
        bytes32[] proof;
    }

    struct MMRLeafPartial {
        uint8 version;
        uint32 parentNumber;
        bytes32 parentHash;
        uint64 nextAuthoritySetID;
        uint32 nextAuthoritySetLen;
        bytes32 nextAuthoritySetRoot;
    }

    struct Proof {
        ParachainHeader header;
        HeadProof headProof;
        MMRLeafPartial leafPartial;
        bytes32[] leafProof;
        uint256 leafProofOrder;
    }

    // Mirrors the Snowbridge binding chain:
    // Verification.sol:113-115 requires the commitment in the header digest.
    // Verification.sol:122-130 hashes encodedParaID plus header into the MMR leaf.
    function verifyCommitment(
        address beefyClient,
        bytes4 encodedParaID,
        bytes32 commitment,
        Proof calldata proof,
        bool isV2
    ) external view returns (bool) {
        if (!isCommitmentInHeaderDigest(commitment, proof.header, isV2)) {
            return false;
        }

        bytes32 parachainHeadHash = createParachainHeaderMerkleLeaf(encodedParaID, proof.header);
        bytes32 parachainHeadsRoot = SubstrateMerkleProofLike.computeRoot(
            parachainHeadHash,
            proof.headProof.pos,
            proof.headProof.width,
            proof.headProof.proof
        );
        bytes32 leafHash = createMMRLeaf(proof.leafPartial, parachainHeadsRoot);
        return IBeefyClientLike(beefyClient).verifyMMRLeafProof(
            leafHash,
            proof.leafProof,
            proof.leafProofOrder
        );
    }

    function isCommitmentInHeaderDigest(
        bytes32 commitment,
        ParachainHeader calldata header,
        bool isV2
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < header.digestItems.length; i++) {
            if (
                header.digestItems[i].data.length == 33
                    && header.digestItems[i].data[0] == DIGEST_ITEM_OTHER_SNOWBRIDGE
                    && commitment == bytes32(header.digestItems[i].data[1:])
            ) {
                return true;
            }
            if (
                isV2
                    && header.digestItems[i].data.length == 33
                    && header.digestItems[i].data[0] == DIGEST_ITEM_OTHER_SNOWBRIDGE_V2
                    && commitment == bytes32(header.digestItems[i].data[1:])
            ) {
                return true;
            }
        }
        return false;
    }

    function createParachainHeaderMerkleLeaf(
        bytes4 encodedParaID,
        ParachainHeader calldata header
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                encodedParaID,
                header.parentHash,
                header.number,
                header.stateRoot,
                header.extrinsicsRoot,
                hashDigestItems(header.digestItems)
            )
        );
    }

    function hashDigestItems(DigestItem[] calldata digestItems)
        internal
        pure
        returns (bytes32)
    {
        bytes32 accumulator;
        for (uint256 i = 0; i < digestItems.length; i++) {
            accumulator = keccak256(abi.encode(accumulator, digestItems[i].data));
        }
        return accumulator;
    }

    function createMMRLeaf(
        MMRLeafPartial memory leaf,
        bytes32 parachainHeadsRoot
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                leaf.version,
                leaf.parentNumber,
                leaf.parentHash,
                leaf.nextAuthoritySetID,
                leaf.nextAuthoritySetLen,
                leaf.nextAuthoritySetRoot,
                parachainHeadsRoot
            )
        );
    }
}
