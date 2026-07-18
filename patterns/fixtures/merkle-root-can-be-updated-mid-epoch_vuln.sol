// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: setMerkleRoot() lets the admin overwrite the live root at any
// time. Any user proof in-flight against the previous root reverts on
// bad-proof. A malicious admin can replace the root with one that
// excludes specific users after observing the mempool.
contract MerkleDistributorVuln {
    address public owner;
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public claimed;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(bytes32 _root) {
        owner = msg.sender;
        merkleRoot = _root;
    }

    // BUG: no timelock, no effective-after, no freeze flag. Rotates
    // the live root with a single call. Every in-flight claim proof
    // built against the previous root now reverts.
    function setMerkleRoot(bytes32 newRoot) external onlyOwner {
        merkleRoot = newRoot;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(!claimed[leaf], "claimed");
        require(_verify(proof, merkleRoot, leaf), "bad proof");
        claimed[leaf] = true;
        // transfer(msg.sender, amount);
    }

    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool)
    {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h < p ? keccak256(abi.encodePacked(h, p))
                      : keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}
