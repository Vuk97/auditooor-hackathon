// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EntropySeedRevealClean {
    uint256 public requestedAtBlock;
    uint256 public confirmations = 8;
    uint256 public latestSeed;

    function requestEntropy() external {
        requestedAtBlock = block.number;
    }

    function revealSeed(bytes32 providerEntropy) external {
        require(confirmations >= 8, "min confirmations");
        uint256 candidateBlock = block.number - confirmations;
        require(isFinalizedBlock(candidateBlock), "unfinalized");
        latestSeed = uint256(
            keccak256(abi.encodePacked(providerEntropy, requestedAtBlock, candidateBlock))
        );
    }

    function isFinalizedBlock(uint256 candidateBlock) internal view returns (bool) {
        return candidateBlock + confirmations < block.number;
    }
}
