// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EntropySeedRevealPositive {
    uint256 public requestedAtBlock;
    uint256 public confirmations = 8;
    uint256 public latestSeed;

    function requestEntropy() external {
        requestedAtBlock = block.number;
    }

    function revealSeed(bytes32 providerEntropy) external {
        require(confirmations >= 8, "min confirmations");
        require(block.number > requestedAtBlock, "pending");
        latestSeed = uint256(
            keccak256(abi.encodePacked(providerEntropy, requestedAtBlock, block.number))
        );
    }
}
