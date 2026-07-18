// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Pausable {
    bool internal _paused;
    function _pause() internal { _paused = true; }
    function _unpause() internal { _paused = false; }
}

contract DexVuln is Pausable {
    // VULN: no access control
    function pause() external { _pause(); }
    function unpause() external { _unpause(); }
}
