// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FreezeControlUnguardedStateFlipClean {
    address public admin;
    bool public paused;
    mapping(address => bool) public blocked;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function pauseTransfers(bool value) external onlyAdmin {
        paused = value;
    }

    function blockAccount(address user, bool value) external onlyAdmin {
        blocked[user] = value;
    }
}
