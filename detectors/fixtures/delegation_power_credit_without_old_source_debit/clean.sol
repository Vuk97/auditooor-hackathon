// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationPowerCreditWithoutOldSourceDebitClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegateOf;
    mapping(address => uint256) public votePowerByDelegate;

    function delegate(address newDelegate) external {
        address oldDelegate = delegateOf[msg.sender];
        uint256 units = balanceOf[msg.sender];

        if (oldDelegate != address(0)) {
            votePowerByDelegate[oldDelegate] -= units;
        }

        delegateOf[msg.sender] = newDelegate;
        votePowerByDelegate[newDelegate] += units;
    }
}
