// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultClean {
    uint256 public idleAssets;
    uint256 public pendingTotal;

    function totalAssets() external view returns (uint256) {
        return idleAssets - pendingTotal;
    }
}
