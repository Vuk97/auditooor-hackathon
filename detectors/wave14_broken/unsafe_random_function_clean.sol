// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnsafeRandomFunctionClean {
    function draw(bytes32 committedSeed) external pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(committedSeed)));
    }
}
