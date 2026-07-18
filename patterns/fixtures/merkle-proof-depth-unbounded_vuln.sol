// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MerkleVerifierVuln {
    function verifyProof(bytes32 root, bytes32 leaf, bytes32[] calldata proof) external pure returns (bool) {
        bytes32 computedHash = leaf;
        // VULN: no upper bound on proof.length
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sib = proof[i];
            computedHash = computedHash < sib
                ? keccak256(abi.encode(computedHash, sib))
                : keccak256(abi.encode(sib, computedHash));
        }
        return computedHash == root;
    }
}
