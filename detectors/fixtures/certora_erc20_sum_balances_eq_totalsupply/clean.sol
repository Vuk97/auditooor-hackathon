// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CleanSupplyAccountingToken {
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
        totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }

    function move(address to, uint256 amount) external {
        _transfer(msg.sender, to, amount);
    }
}
