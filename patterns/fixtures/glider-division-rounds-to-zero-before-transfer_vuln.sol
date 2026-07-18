// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function safeTransferFrom(address from, address to, uint256 amount) external;
    function safeTransfer(address to, uint256 amount) external;
}

contract AssimilatorVuln {
    IERC20 public token;
    uint256 public constant DECIMALS = 1e8;
    uint256 public rate;
    mapping(address => uint256) public shares;

    function deposit(uint256 _amount) external {
        uint256 amount = (_amount * DECIMALS) / rate;
        token.safeTransferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += _amount;
    }
}