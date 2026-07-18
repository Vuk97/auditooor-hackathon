// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteNFTVuln {
    struct Checkpoint { uint32 block; uint224 votes; }
    mapping(uint256 => Checkpoint[]) public checkpoints;

    function _update(address from, address to, uint256 id) internal {
        // VULN: delete destroys historical vote record
        delete checkpoints[id];
    }

    function transferFrom(address from, address to, uint256 id) external {
        _update(from, to, id);
    }
}
