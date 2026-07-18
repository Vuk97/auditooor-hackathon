// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultVuln {
    uint256 public idleAssets;
    mapping(address => uint256) public pendingWithdraw;
    address[] public withdrawQueue;

    /// VULN: totalAssets adds pendingWithdraw entries forever.
    function totalAssets() external view returns (uint256 total) {
        total = idleAssets;
        for (uint256 i = 0; i < withdrawQueue.length; i++) {
            total += pendingWithdraw[withdrawQueue[i]];
        }
    }
}
