// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: delegation moves power, removing it from the prior delegate first.
contract DelegationPowerInflationSafe {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegationPower;
    mapping(address => address) public delegateOf;

    function delegate(address to) external {
        address prev = delegateOf[msg.sender];
        if (prev != address(0)) {
            delegationPower[prev] -= balanceOf[msg.sender];
        }
        delegateOf[msg.sender] = to;
        delegationPower[to] += balanceOf[msg.sender];
    }
}
