// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PlonkVerifierSafe {
    uint256 constant R_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // SAFE: explicit non-zero guard before Fermat-based inverse. Zero has no
    // multiplicative inverse in the prime field, so reject it rather than
    // silently returning 0.
    function inverse(uint256 a) internal view returns (uint256 result) {
        require(a != 0, "zero has no inverse");
        uint256 p = R_MOD;
        uint256[6] memory input;
        input[0] = 0x20;
        input[1] = 0x20;
        input[2] = 0x20;
        input[3] = a;
        input[4] = p - 2;
        input[5] = p;
        assembly {
            if iszero(staticcall(gas(), 0x05, input, 0xc0, result, 0x20)) {
                revert(0, 0)
            }
        }
    }
}
