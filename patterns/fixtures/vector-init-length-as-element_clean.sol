// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// CLEAN: dynamic array is allocated with the *length* argument, not capacity 1.
contract BatchProcessorClean {
    function plan(uint256 totalLen) external pure returns (uint256[] memory) {
        uint256[] memory out = new uint256[](totalLen); // correct: len-sized
        for (uint256 i = 0; i < totalLen; ++i) {
            out[i] = i;
        }
        return out;
    }

    function dispatch(bytes[] calldata payloads) external pure returns (bytes32[] memory) {
        uint256 numPayloads = payloads.length;
        bytes32[] memory digests = new bytes32[](numPayloads); // correct
        for (uint256 i = 0; i < numPayloads; ++i) {
            digests[i] = keccak256(payloads[i]);
        }
        return digests;
    }
}
