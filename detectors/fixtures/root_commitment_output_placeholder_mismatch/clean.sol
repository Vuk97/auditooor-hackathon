// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RootCommitmentOutputPlaceholderMismatchClean {
    bytes32 public committedRoot;
    bytes32 public publishedRoot;

    event BatchCommitted(bytes32 root, bytes32 computedRoot);

    function commitBatch(bytes32[] calldata leaves, bytes32 expectedRoot) external returns (bytes32) {
        bytes32 nextRoot = committedRoot;
        for (uint256 i = 0; i < leaves.length; i++) {
            nextRoot = keccak256(abi.encodePacked(nextRoot, leaves[i]));
        }

        committedRoot = nextRoot;
        require(expectedRoot == nextRoot, "root mismatch");
        publishedRoot = nextRoot;
        emit BatchCommitted(nextRoot, nextRoot);
        return nextRoot;
    }
}
