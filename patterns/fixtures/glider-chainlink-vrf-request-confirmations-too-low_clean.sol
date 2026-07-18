// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVRFV2 {
    function requestRandomWords(bytes32 keyHash, uint64 subId, uint16 confirmations, uint32 gasLimit, uint32 numWords) external returns (uint256);
}

contract VRFRequestConfirmationsLowClean {
    IVRFV2 public coord;
    uint16 public constant CONF = 20;
    function draw() external returns (uint256) {
        return coord.requestRandomWords(bytes32(0), 1, CONF, 200000, 1);
    }
}
