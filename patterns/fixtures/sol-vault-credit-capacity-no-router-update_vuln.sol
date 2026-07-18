// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultRouterVuln {
    uint256 public assetsUnderManagement;
    function deposit(uint256 a) external {
        assetsUnderManagement += a;
    }
}
