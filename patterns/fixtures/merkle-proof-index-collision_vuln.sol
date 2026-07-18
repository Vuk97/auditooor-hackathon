// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address, uint256) external returns (bool); }

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h < p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}

contract MerkleAirdropVuln {
    bytes32 public merkleRoot;
    IERC20Like public token;

    constructor(bytes32 _root, address _token) {
        merkleRoot = _root;
        token = IERC20Like(_token);
    }

    // VULN: proof is verified but no `claimed[leaf]` flag is ever set.
    // The same (msg.sender, amount, proof) triple can be replayed forever.
    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(msg.sender, amount);
    }
}
