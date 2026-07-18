// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MissingOrInsufficientAccessControlOnPausableFunctionsPositive {
    bool public paused;

    function _pause() internal {
        paused = true;
    }

    function _unpause() internal {
        paused = false;
    }

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }
}
