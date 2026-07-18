// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationPowerStaleSourceRetentionPositive {
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegateOf;
    mapping(address => uint256) public delegationPower;

    function delegate(address newDelegate) external {
        address oldDelegate = delegateOf[msg.sender];
        delegateOf[msg.sender] = newDelegate;
        delegationPower[newDelegate] += balanceOf[msg.sender];
        oldDelegate;
    }
}
