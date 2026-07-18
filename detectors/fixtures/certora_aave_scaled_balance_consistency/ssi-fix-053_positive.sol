// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CertoraAaveScaledBalanceConsistencyPositive {
    mapping(address => uint256) internal _balances;
    mapping(address => uint256) internal _scaledBalances;
    uint256 internal _totalSupply;
    uint256 internal _scaledTotalSupply;
    uint256 public liquidityIndex;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        liquidityIndex = 1_000_000_000_000_000_000_000_000_000;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function scaledTotalSupply() external view returns (uint256) {
        return _scaledTotalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function scaledBalanceOf(address account) external view returns (uint256) {
        return _scaledBalances[account];
    }

    function credit(address user, uint256 amount) external {
        _balances[user] += amount;
        _totalSupply += amount;
        emit Transfer(address(0), user, amount);
    }
}
