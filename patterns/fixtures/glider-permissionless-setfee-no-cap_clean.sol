// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultClean {
    uint256 public performanceFee;
    uint256 public constant MAX_FEE_BPS = 2000;
    address public owner;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function setPerformanceFee(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE_BPS, "cap");
        performanceFee = newFee;
    }
}
