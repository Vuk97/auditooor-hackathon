// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Pausable {
    bool internal _paused;
    function _pause() internal { _paused = true; }
    function _unpause() internal { _paused = false; }
}

contract VaultPauseVuln is Pausable {
    uint256 public totalAssets;

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }

    function deposit(uint256 assets) external {
        require(!_paused, "paused");
        totalAssets += assets;
    }
}