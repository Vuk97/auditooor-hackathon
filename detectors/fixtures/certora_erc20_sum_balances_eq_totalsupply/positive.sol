// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BrokenSupplyAccountingToken {
    mapping(address => uint256) internal _balances;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor() {
        _balances[msg.sender] = 100 ether;
        totalSupply = 100 ether;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function credit(address account, uint256 amount) external {
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }
}
