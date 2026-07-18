// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PayoutVuln {
    IERC20 public token;
    mapping(address => uint256) public paidOut;
    function pay(address user, uint256 amount) external {
        // VULN: return value ignored
        token.transfer(user, amount);
        paidOut[user] += amount;
    }
}
