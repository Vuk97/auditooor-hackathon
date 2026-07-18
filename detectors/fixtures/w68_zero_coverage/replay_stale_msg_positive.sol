// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: a stale message can be replayed - no expiry/deadline check
// and no consumed-message bookkeeping.
contract ReplayStaleMsgVulnerable {
    mapping(address => uint256) public credited;

    function executeMessage(address to, uint256 amount, uint256 issuedAt) external {
        credited[to] += amount;
    }
}
