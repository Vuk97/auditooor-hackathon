// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeTokenVuln {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public isBridgedTokenHolder; // permanent flag

    // VULN: sets irrevocable flag on any recipient (even 1 wei bridge)
    function _creditBridged(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        isBridgedTokenHolder[to] = true;
    }

    function bridgeIn(address to, uint256 amount) external {
        _creditBridged(to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (isBridgedTokenHolder[msg.sender]) {
            // bridged holders can only move once per day, etc.
            revert("bridged-holder restriction");
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
