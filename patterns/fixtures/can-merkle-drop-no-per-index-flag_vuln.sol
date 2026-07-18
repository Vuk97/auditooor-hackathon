// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MerkleProof {
    function verify(bytes32[] calldata, bytes32, bytes32) internal pure returns (bool) { return true; }
}

interface IERC20 { function transfer(address, uint256) external returns (bool); }

contract AirdropVuln {
    bytes32 public merkleRoot;
    IERC20 public token;

    // BUG: verifies proof + transfers — no claimed[index] flag. Proof replayable.
    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(account, amount);
    }
}
