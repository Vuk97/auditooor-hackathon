// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CollateralHealthCheckBypassViaPayInterestVuln {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] * 85 / 100 >= debt[msg.sender] + amount, "unsafe");
        debt[msg.sender] += amount;
    }

    function payInterest(uint256 fromCollateral) external {
        // VULN: decrements collateral without health check.
        collateral[msg.sender] -= fromCollateral;
    }
}
