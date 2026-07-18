// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Pausable {
    bool internal _paused;
    function _pause() internal { _paused = true; }
    function _unpause() internal { _paused = false; }
    modifier whenNotPaused() { require(!_paused); _; }
}

contract ProtocolClean is Pausable {
    address public admin;
    constructor() { admin = msg.sender; }
    function pause() external { require(msg.sender == admin); _pause(); }
    function unpause() external { require(msg.sender == admin); _unpause(); }
    function doThing() external whenNotPaused {}
}
