// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NodeExitBlocksOtherNodesPositive {
    mapping(uint256 => bytes32[]) internal schains;
    mapping(uint256 => uint256) internal cursor;

    function seed(uint256 nodeId, bytes32 schainA, bytes32 schainB) external {
        delete schains[nodeId];
        schains[nodeId].push(schainA);
        schains[nodeId].push(schainB);
    }

    function nodeExit(uint256 nodeId) external returns (bool) {
        require(schains[nodeId].length > 0, "no schains");

        bytes32 schainId = schains[nodeId][schains[nodeId].length - 1];
        _detachOneSchain(nodeId, schainId);
        schains[nodeId].pop();
        cursor[nodeId] += 1;

        if (schains[nodeId].length == 0) {
            delete schains[nodeId];
        }

        return true;
    }

    function _detachOneSchain(uint256, bytes32) internal {}
}
