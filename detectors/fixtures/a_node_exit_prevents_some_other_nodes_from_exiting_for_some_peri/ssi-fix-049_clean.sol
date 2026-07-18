// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NodeExitBlocksOtherNodesClean {
    mapping(uint256 => bytes32[]) internal schains;
    mapping(uint256 => uint256) internal cursor;

    function seed(uint256 nodeId, bytes32 schainA, bytes32 schainB) external {
        delete schains[nodeId];
        schains[nodeId].push(schainA);
        schains[nodeId].push(schainB);
    }

    function nodeExit(uint256 nodeId) external returns (bool) {
        require(schains[nodeId].length > 0, "no schains");

        uint256 pending = schains[nodeId].length;
        for (uint256 i = 0; i < pending; ++i) {
            bytes32 schainId = schains[nodeId][pending - 1 - i];
            _detachOneSchain(nodeId, schainId);
        }

        delete schains[nodeId];
        cursor[nodeId] += pending;
        return true;
    }

    function _detachOneSchain(uint256, bytes32) internal {}
}
