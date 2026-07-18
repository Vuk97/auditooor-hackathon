// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FreezeControlUnguardedStateFlipPositive {
    address public admin;
    bool public paused;
    mapping(address => bool) public blocked;

    function pauseTransfers(bool value) external {
        paused = value;
    }

    function blockAccount(address user, bool value) external {
        blocked[user] = value;
    }
}
