// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PayoutClean {
    IERC20 public token;
    mapping(address => uint256) public paidOut;
    function pay(address user, uint256 amount) external {
        bool ok = token.transfer(user, amount);
        require(ok, "transfer fail");
        paidOut[user] += amount;
    }
}
