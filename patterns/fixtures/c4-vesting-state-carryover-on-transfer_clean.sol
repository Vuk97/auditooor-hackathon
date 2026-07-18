// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VestingClean {
    struct Vesting { uint256 total; uint256 stepsClaimed; address owner; }
    mapping(uint256 => Vesting) public vestings;
    uint256 public nextId;

    function transferVesting(uint256 id, address to) external {
        Vesting storage v = vestings[id];
        require(v.owner == msg.sender);
        // CLEAN: propagate stepsClaimed
        vestings[nextId] = Vesting({total: v.total, stepsClaimed: v.stepsClaimed, owner: to});
        nextId += 1;
        delete vestings[id];
    }
}
