// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ApphashDivergenceNondeterministicRootInputClean {
    bytes32 public checkpointRoot;

    event CheckpointFinalized(bytes32 checkpointRoot);

    function finalizeCheckpoint(bytes32[] calldata leaves, bytes32 expectedRoot) external returns (bytes32) {
        bytes32 nextRoot = bytes32(0);

        for (uint256 i = 0; i < leaves.length; i++) {
            require(i == 0 || leaves[i - 1] < leaves[i], "leaves not sorted");
            nextRoot = keccak256(abi.encodePacked(nextRoot, leaves[i]));
        }

        require(expectedRoot == nextRoot, "root mismatch");
        checkpointRoot = nextRoot;
        emit CheckpointFinalized(nextRoot);
        return nextRoot;
    }
}
