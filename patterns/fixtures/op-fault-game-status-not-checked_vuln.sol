// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDisputeGame {
    function rootClaim() external view returns (bytes32);
    function status() external view returns (uint8);
    function resolvedAt() external view returns (uint64);
}

contract OPFaultVerifierVuln {
    // VULN: reads rootClaim without checking status/resolution
    function verifyRootFromGame(IDisputeGame game, bytes32 expected) external view returns (bool) {
        bytes32 r = game.rootClaim();
        return r == expected;
    }
}
