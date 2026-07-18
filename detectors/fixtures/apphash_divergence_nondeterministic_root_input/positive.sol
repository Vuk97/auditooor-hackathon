// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ApphashDivergenceNondeterministicRootInputPositive {
    bytes32[] public pendingLeaves;
    bytes32 public checkpointRoot;

    event CheckpointFinalized(bytes32 checkpointRoot);

    function enqueue(bytes32 leaf) external {
        pendingLeaves.push(leaf);
    }

    function finalizeCheckpoint() external returns (bytes32) {
        bytes32 nextRoot = bytes32(0);

        for (uint256 i = 0; i < pendingLeaves.length; i++) {
            nextRoot = keccak256(
                abi.encodePacked(nextRoot, pendingLeaves[i], block.timestamp)
            );
        }

        checkpointRoot = nextRoot;
        emit CheckpointFinalized(checkpointRoot);
        return checkpointRoot;
    }
}
