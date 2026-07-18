// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MissingOrInsufficientAccessControlOnPausableFunctionsClean {
    bool public paused;
    address private owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _pause() internal {
        paused = true;
    }

    function _unpause() internal {
        paused = false;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
