// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationPowerCreditWithoutDebitVulnerable {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegationPower;
    mapping(address => address) public delegateOf;

    function delegate(address to) external {
        delegationPower[to] += balanceOf[msg.sender];
        delegateOf[msg.sender] = to;
    }
}
