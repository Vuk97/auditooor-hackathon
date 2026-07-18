// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenClean {
    mapping(address => mapping(address => uint256)) internal _allowances;
    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }
}
