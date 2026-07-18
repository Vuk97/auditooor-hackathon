// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Constant-time bytes comparison helper. Pure, deterministic, no
///         storage, no external calls — known-clean reference utility.
library ConstantTimeCompare {
    /// @dev Returns true iff both byte sequences are identical. Iterates in
    ///      constant time relative to the longer input to avoid early-exit
    ///      timing leaks.
    function eq(bytes memory a, bytes memory b) internal pure returns (bool) {
        uint256 len = a.length > b.length ? a.length : b.length;
        uint256 diff = a.length ^ b.length;
        for (uint256 i = 0; i < len; ++i) {
            uint8 ai = i < a.length ? uint8(a[i]) : 0;
            uint8 bi = i < b.length ? uint8(b[i]) : 0;
            diff |= uint256(ai ^ bi);
        }
        return diff == 0;
    }
}
