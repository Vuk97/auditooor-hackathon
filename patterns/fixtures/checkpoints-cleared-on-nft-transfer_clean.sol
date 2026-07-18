// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteNFTClean {
    struct Checkpoint { uint32 block; uint224 votes; }
    mapping(uint256 => Checkpoint[]) public checkpoints;
    mapping(uint256 => uint224) public currentVotes;

    function _update(address from, address to, uint256 id) internal {
        // CLEAN: append new checkpoint rather than deleting history
        checkpoints[id].push(Checkpoint({block: uint32(block.number), votes: currentVotes[id]}));
    }

    function transferFrom(address from, address to, uint256 id) external {
        _update(from, to, id);
    }
}
