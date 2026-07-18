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

contract SnowbridgeCommitmentBindingMissingPositive {
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
        HeadProof headProof;
        MMRLeafPartial leafPartial;
        bytes32 unboundParachainHeadHash;
        bytes32[] leafProof;
        uint256 leafProofOrder;
    }

    // Models the missing half of Snowbridge Verification.sol:106-135.
    // A caller supplies the settlement commitment, but the MMR proof is built
    // from an already-supplied parachain head hash that does not prove the
    // commitment was inside the header digest for the encoded parachain id.
    function verifyCommitment(
        address beefyClient,
        bytes4 encodedParaID,
        bytes32 commitment,
        Proof calldata proof
    ) external view returns (bool) {
        encodedParaID;
        commitment;

        bytes32 parachainHeadsRoot = SubstrateMerkleProofLike.computeRoot(
            proof.unboundParachainHeadHash,
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
