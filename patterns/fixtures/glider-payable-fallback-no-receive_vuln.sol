// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultFallbackVuln {
    uint256 public total;
    /// VULN: payable fallback without a dedicated receive()
    fallback() external payable {
        total += msg.value;
    }
}
