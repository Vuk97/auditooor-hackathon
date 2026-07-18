// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationPowerRedelegateWithoutSourceBurnPositive {
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegateOf;
    mapping(address => uint256) public delegationPower;

    function redelegate(address newDelegate) external {
        address oldDelegate = delegateOf[msg.sender];
        uint256 units = balanceOf[msg.sender];

        delegateOf[msg.sender] = newDelegate;
        delegationPower[newDelegate] += units;
        oldDelegate;
    }
}
