// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RaffleVuln {
    mapping(uint256 => address) public winner;

    /// VULN: timestamp-hashed modulo as randomness.
    function draw(uint256 roundId, uint256 numEntries) external {
        uint256 r = uint256(keccak256(abi.encode(block.timestamp, block.number, msg.sender))) % numEntries;
        winner[roundId] = address(uint160(r + 1));
    }
}
