// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BitmapProofVerifierPositive {
    function verifyProof(
        bytes32[] calldata leafKeys,
        bytes calldata bitmap,
        bytes32[] calldata siblings
    ) external pure returns (bytes32 computedRoot) {
        uint256 siblingIndex = 0;

        for (uint256 byteIndex = 0; byteIndex < bitmap.length; byteIndex++) {
            uint8 mask = uint8(bitmap[byteIndex]);
            for (
                uint256 bitIndex = 0;
                bitIndex < 8 && (byteIndex * 8 + bitIndex) < leafKeys.length;
                bitIndex++
            ) {
                if ((mask & (1 << bitIndex)) != 0) {
                    computedRoot = keccak256(
                        abi.encodePacked(computedRoot, siblings[siblingIndex])
                    );
                    siblingIndex++;
                } else {
                    computedRoot = keccak256(
                        abi.encodePacked(computedRoot, leafKeys[byteIndex * 8 + bitIndex])
                    );
                }
            }
        }
    }
}
