// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationPowerCreditWithoutDebitSafe {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegationPower;
    mapping(address => address) public delegateOf;

    function delegate(address to) external {
        address oldDelegate = delegateOf[msg.sender];
        if (oldDelegate != address(0)) {
            delegationPower[oldDelegate] -= balanceOf[msg.sender];
        }
        delegateOf[msg.sender] = to;
        delegationPower[to] += balanceOf[msg.sender];
    }
}
