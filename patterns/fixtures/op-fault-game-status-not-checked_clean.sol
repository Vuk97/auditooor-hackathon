// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDisputeGame {
    function rootClaim() external view returns (bytes32);
    function status() external view returns (uint8);
    function resolvedAt() external view returns (uint64);
}

contract OPFaultVerifierClean {
    uint8 constant DEFENDER_WINS = 2;
    uint256 constant AIRGAP_SECONDS = 7 days;

    function verifyRootFromGame(IDisputeGame game, bytes32 expected) external view returns (bool) {
        require(game.status() == DEFENDER_WINS, "game not resolved");
        require(block.timestamp >= uint256(game.resolvedAt()) + AIRGAP_SECONDS, "airgap");
        bytes32 r = game.rootClaim();
        return r == expected;
    }
}
