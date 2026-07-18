// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ValidateSPVClean {
    function verifyHash256Merkle(bytes32 txid, bytes memory proof, uint256 index, bytes32 root) internal pure returns (bool) {
        bytes32 h = txid;
        for (uint256 i = 0; i < proof.length / 32; i++) {
            bytes32 sibling;
            assembly { sibling := mload(add(proof, add(32, mul(i, 32)))) }
            if (index % 2 == 0) {
                h = sha256(abi.encodePacked(sha256(abi.encodePacked(h, sibling))));
            } else {
                h = sha256(abi.encodePacked(sha256(abi.encodePacked(sibling, h))));
            }
            index /= 2;
        }
        return h == root;
    }
}

contract SpvProofClean {
    // FIXED: reject 64-byte tx preimages and require coinbase proof length
    // matches tx proof length.
    function prove(
        bytes calldata txBytes,
        bytes32 txId,
        bytes calldata merkleProof,
        uint256 index,
        bytes32 coinbaseTxId,
        bytes calldata coinbaseProof,
        uint256 coinbaseIndex,
        bytes32 merkleRoot
    ) external pure returns (bool) {
        require(txBytes.length != 64, "64-byte tx rejected");
        require(merkleProof.length == coinbaseProof.length, "proof length mismatch");
        require(ValidateSPVClean.verifyHash256Merkle(coinbaseTxId, coinbaseProof, coinbaseIndex, merkleRoot), "bad coinbase");
        return ValidateSPVClean.verifyHash256Merkle(txId, merkleProof, index, merkleRoot);
    }
}
