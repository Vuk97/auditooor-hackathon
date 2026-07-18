// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: setMerkleRoot() is gated by a timelock — new root only
// becomes effective after a scheduled delay, giving in-flight proofs
// a deterministic deadline to land. The setter itself contains an
// `effectiveAfter` / `timelock` check that the pattern body-regex
// filters out as a guard.
contract MerkleDistributorClean {
    address public owner;
    bytes32 public merkleRoot;
    bytes32 public pendingRoot;
    uint256 public effectiveAfter;
    uint256 public constant ROOT_TIMELOCK = 2 days;
    mapping(bytes32 => bool) public claimed;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(bytes32 _root) {
        owner = msg.sender;
        merkleRoot = _root;
    }

    // FIX: admin schedules a new root with a timelock; it only lands
    // after `effectiveAfter`. In-flight proofs against the current
    // root have a visible deadline.
    function setMerkleRoot(bytes32 newRoot) external onlyOwner {
        // timelock: schedule a new root, do not overwrite the live one.
        if (pendingRoot != bytes32(0) && block.timestamp >= effectiveAfter) {
            merkleRoot = pendingRoot;
            pendingRoot = bytes32(0);
            effectiveAfter = 0;
        }
        pendingRoot = newRoot;
        effectiveAfter = block.timestamp + ROOT_TIMELOCK;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(!claimed[leaf], "claimed");
        require(_verify(proof, merkleRoot, leaf), "bad proof");
        claimed[leaf] = true;
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
