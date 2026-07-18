// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LendingVuln {
    mapping(address => uint256) public debt;
    uint256 public rate = 1e15; // per block
    uint256 public constant SCALE = 1e18;

    function borrow(uint256 amount) external {
        // VULN: interest rounds to zero for dust loans
        uint256 interest = debt[msg.sender] * rate / SCALE;
        debt[msg.sender] += amount + interest;
    }
}
