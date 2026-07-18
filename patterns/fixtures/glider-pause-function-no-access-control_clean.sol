// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Pausable {
    bool internal _paused;
    function _pause() internal { _paused = true; }
    function _unpause() internal { _paused = false; }
}

contract VaultPauseClean is Pausable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}