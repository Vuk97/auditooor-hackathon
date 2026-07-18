// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library WadRayMath {
    uint256 internal constant RAY = 1e27;

    function rayDiv(uint256 amount, uint256 index) internal pure returns (uint256) {
        return (amount * RAY) / index;
    }

    function rayMul(uint256 amount, uint256 index) internal pure returns (uint256) {
        return (amount * index) / RAY;
    }
}

contract CertoraAaveScaledBalanceConsistencyClean {
    using WadRayMath for uint256;

    mapping(address => uint256) internal _balances;
    mapping(address => uint256) internal _scaledBalances;
    uint256 internal _totalSupply;
    uint256 internal _scaledTotalSupply;
    uint256 public liquidityIndex;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        liquidityIndex = WadRayMath.RAY;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function scaledTotalSupply() external view returns (uint256) {
        return _scaledTotalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _scaledBalances[account].rayMul(liquidityIndex);
    }

    function scaledBalanceOf(address account) external view returns (uint256) {
        return _scaledBalances[account];
    }

    function credit(address user, uint256 amount) external {
        uint256 scaledDelta = amount.rayDiv(liquidityIndex);
        _scaledBalances[user] += scaledDelta;
        _scaledTotalSupply += scaledDelta;
        _balances[user] = _scaledBalances[user].rayMul(liquidityIndex);
        _totalSupply = _scaledTotalSupply.rayMul(liquidityIndex);
        emit Transfer(address(0), user, amount);
    }
}
