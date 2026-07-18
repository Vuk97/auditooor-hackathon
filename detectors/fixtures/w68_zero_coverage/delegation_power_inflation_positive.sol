// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: delegate adds power to the delegatee without subtracting it
// from the delegator - delegation power is inflated by double-counting.
contract DelegationPowerInflationVulnerable {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegationPower;

    function delegate(address to) external {
        delegationPower[to] += balanceOf[msg.sender];
    }
}
