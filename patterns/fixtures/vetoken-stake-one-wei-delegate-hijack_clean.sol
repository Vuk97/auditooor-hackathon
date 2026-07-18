// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VeTokenClean {
    mapping(address => address) public delegates;
    mapping(address => uint256) public balance;

    function stake(address user, uint256 amount, address newDelegate) external {
        balance[user] += amount;
        // CLEAN: only set delegate if caller == user, or delegate unset
        if (delegates[user] == address(0) || msg.sender == user) {
            delegates[user] = newDelegate;
        }
    }
}
