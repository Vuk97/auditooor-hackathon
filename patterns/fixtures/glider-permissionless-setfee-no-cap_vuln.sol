// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultVuln {
    uint256 public performanceFee;

    // VULN: no access control, no cap
    function setPerformanceFee(uint256 newFee) external {
        performanceFee = newFee;
    }
}
