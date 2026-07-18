// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: message carries a deadline and a unique id consumed once.
contract ReplayStaleMsgSafe {
    mapping(address => uint256) public credited;
    mapping(bytes32 => bool) public consumed;

    function executeMessage(address to, uint256 amount, uint256 deadline, bytes32 msgId) external {
        require(block.timestamp <= deadline, "stale message");
        require(!consumed[msgId], "already replayed");
        consumed[msgId] = true;
        credited[to] += amount;
    }
}
