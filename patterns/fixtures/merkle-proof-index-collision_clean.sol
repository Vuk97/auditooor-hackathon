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

contract MerkleAirdropClean {
    bytes32 public merkleRoot;
    IERC20Like public token;

    // CLEAN: per-leaf consumed flag prevents replay.
    mapping(bytes32 => bool) public claimed;

    constructor(bytes32 _root, address _token) {
        merkleRoot = _root;
        token = IERC20Like(_token);
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(!claimed[leaf], "already claimed");
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        claimed[leaf] = true;
        token.transfer(msg.sender, amount);
    }
}
