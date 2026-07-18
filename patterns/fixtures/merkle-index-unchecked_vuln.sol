// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MerkleProof {
    function verifyProof(bytes32[] memory, bytes32, bytes32) internal pure returns (bool) { return true; }
}

contract AirdropVuln {
    bytes32 public merkleRoot;

    /// VULN: user-supplied index never bounded against leaf count.
    function claim(uint256 index, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(index, msg.sender, amount));
        require(MerkleProof.verifyProof(proof, merkleRoot, leaf), "bad proof");
        // would pay amount
    }
}
