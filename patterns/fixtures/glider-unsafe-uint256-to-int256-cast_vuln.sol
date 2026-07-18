// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract CastVuln {
    function signedDelta(uint256 a, uint256 b) external pure returns (int256) {
        // VULN: no bound check before int256 cast
        return int256(a) - int256(b);
    }
}
