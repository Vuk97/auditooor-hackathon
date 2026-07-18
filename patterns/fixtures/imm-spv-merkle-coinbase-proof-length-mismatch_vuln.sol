// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ValidateSPV {
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

contract SpvProofVuln {
    // VULN: merkle prove with no coinbase length check and no 64-byte tx
    // rejection. Allows the 64-byte tx / internal-node collision.
    function prove(
        bytes32 txId,
        bytes calldata merkleProof,
        uint256 index,
        bytes32 merkleRoot
    ) external pure returns (bool) {
        return ValidateSPV.verifyHash256Merkle(txId, merkleProof, index, merkleRoot);
    }
}
