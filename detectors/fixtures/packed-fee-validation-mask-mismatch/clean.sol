// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PackedFeeValidationMaskMismatchClean {
    uint24 public lastComputedFee;

    function quote(uint24 self, uint24 lpFee, bool zeroForOne) external returns (uint24) {
        uint24 swapFee = calculateSwapFee(self, lpFee, zeroForOne);
        lastComputedFee = swapFee;
        return swapFee;
    }

    function calculateSwapFee(
        uint24 self,
        uint24 lpFee,
        bool zeroForOne
    ) internal returns (uint24 swapFee) {
        assembly ("memory-safe") {
            switch zeroForOne
            case 1 {
                swapFee := add(lpFee, and(self, 0xfff))
            }
            default {
                swapFee := add(lpFee, and(shr(12, self), 0xfff))
            }
        }

        lastComputedFee = swapFee;
    }
}
