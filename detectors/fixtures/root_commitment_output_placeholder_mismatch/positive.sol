// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RootCommitmentOutputPlaceholderMismatchPositive {
    bytes32 public committedRoot;
    bytes32 public lastPublishedRoot;
    bytes32 public publishedRoot;

    event BatchCommitted(bytes32 root, bytes32 computedRoot);

    function commitBatch(bytes32[] calldata leaves, bytes32 expectedRoot) external returns (bytes32) {
        bytes32 nextRoot = committedRoot;
        for (uint256 i = 0; i < leaves.length; i++) {
            nextRoot = keccak256(abi.encodePacked(nextRoot, leaves[i]));
        }

        committedRoot = nextRoot;

        bytes32 outputRoot = lastPublishedRoot;
        require(expectedRoot == outputRoot, "root mismatch");
        publishedRoot = outputRoot;
        emit BatchCommitted(outputRoot, nextRoot);
        return outputRoot;
    }
}
