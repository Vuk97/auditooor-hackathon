// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IChainlinkVRF { function requestRandomness(bytes32, uint256) external returns (bytes32); }

contract RaffleClean {
    IChainlinkVRF public vrf;
    mapping(bytes32 => uint256) public requestToRound;

    function draw(uint256 roundId, uint256 numEntries) external {
        numEntries;
        bytes32 req = vrf.requestRandomness(bytes32(0), 0);
        requestToRound[req] = roundId;
    }
}
