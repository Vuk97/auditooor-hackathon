// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StorageRootAssignmentMissingClean {
    bytes32 public committedRoot;

    function finalizeTree(bytes32[] calldata leaves) external returns (bytes32) {
        bytes32 computedRoot = committedRoot;
        for (uint256 i = 0; i < leaves.length; i++) {
            computedRoot = keccak256(abi.encodePacked(computedRoot, leaves[i]));
        }
        committedRoot = computedRoot;
        emit Finalized(committedRoot);
        return committedRoot;
    }

    event Finalized(bytes32 root);
}
