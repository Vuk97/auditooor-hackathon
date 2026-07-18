// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MerkleProof {
    function verifyProof(bytes32[] memory, bytes32, bytes32) internal pure returns (bool) { return true; }
}

contract AirdropClean {
    bytes32 public merkleRoot;
    uint256 public constant TREE_SIZE = 65536;

    /// CLEAN: bounds index to declared tree size.
    function claim(uint256 index, uint256 amount, bytes32[] calldata proof) external {
        require(index < TREE_SIZE, "index oob");
        bytes32 leaf = keccak256(abi.encodePacked(index, msg.sender, amount));
        require(MerkleProof.verifyProof(proof, merkleRoot, leaf), "bad proof");
    }
}
