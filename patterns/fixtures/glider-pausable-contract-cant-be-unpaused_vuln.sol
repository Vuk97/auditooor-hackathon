// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Pausable {
    bool internal _paused;
    function _pause() internal { _paused = true; }
    function _unpause() internal { _paused = false; }
    modifier whenNotPaused() { require(!_paused); _; }
}

contract ProtocolVuln is Pausable {
    address public admin;
    constructor() { admin = msg.sender; }
    // VULN: only pause exposed; no way to unpause
    function pause() external { require(msg.sender == admin); _pause(); }
    function doThing() external whenNotPaused {}
}
