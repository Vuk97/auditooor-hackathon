// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StorageRootAssignmentMissingPositive {
    bytes32 public committedRoot;

    function finalizeTree(bytes32[] calldata leaves) external returns (bytes32) {
        bytes32 storageRoot;
        for (uint256 i = 0; i < leaves.length; i++) {
            committedRoot = keccak256(abi.encodePacked(committedRoot, leaves[i]));
        }
        emit Finalized(storageRoot);
        return storageRoot;
    }

    event Finalized(bytes32 root);
}
