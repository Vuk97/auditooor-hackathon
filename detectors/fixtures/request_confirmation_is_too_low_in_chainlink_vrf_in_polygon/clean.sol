// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface VRFCoordinatorV2Interface {
    function requestRandomWords(
        bytes32 keyHash,
        uint64 subId,
        uint16 requestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external returns (uint256 requestId);
}

contract RequestConfirmationsTooLowOnPolygonClean {
    VRFCoordinatorV2Interface internal coordinator;
    bytes32 internal keyHash;
    uint64 internal subscriptionId;

    function requestWinner() external returns (uint256 requestId) {
        return coordinator.requestRandomWords(keyHash, subscriptionId, 3, 200000, 1);
    }
}
