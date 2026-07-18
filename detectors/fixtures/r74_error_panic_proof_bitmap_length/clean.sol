// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BitmapProofVerifierClean {
    uint256 internal constant MAX_BITMAP_BYTES = 32;
    uint256 internal constant MAX_DEPTH = 256;

    function verifyProof(
        bytes32[] calldata leafKeys,
        bytes calldata bitmap,
        bytes32[] calldata siblings
    ) external pure returns (bytes32 computedRoot) {
        require(bitmap.length > 0, "empty bitmap");
        require(bitmap.length <= MAX_BITMAP_BYTES, "bitmap too deep");
        require(siblings.length <= MAX_DEPTH, "too many siblings");
        require(leafKeys.length <= bitmap.length * 8, "bitmap leaf mismatch");

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
