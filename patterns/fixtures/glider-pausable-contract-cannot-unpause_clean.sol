// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

abstract contract Pausable {
    bool internal _paused;
    modifier whenNotPaused() { require(!_paused, "paused"); _; }
    function _pause() internal virtual { _paused = true; }
    function _unpause() internal virtual { _paused = false; }
}

contract VaultCleanUnp is Pausable {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    function work() external whenNotPaused {}
}
