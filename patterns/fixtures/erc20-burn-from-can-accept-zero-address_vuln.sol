// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: burnFrom() takes an `address account` and decrements both
// balances[account] and totalSupply with no zero-address guard. On
// this 0.8 compile it will revert on underflow when account is
// address(0), but that revert is itself a griefing vector for any
// batched caller. On pre-0.8 or `unchecked`-wrapped variants the
// null-address balance is silently corrupted.
contract TokenVuln {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // BUG: no zero-address guard on `account`. Any caller with a
    // non-zero allowance against address(0) (or any caller on impls
    // without the allowance check) can reach the balance/totalSupply
    // writes with account == address(0).
    function burnFrom(address account, uint256 amount) external {
        uint256 allowed = allowance[account][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[account][msg.sender] = allowed - amount;
        }
        balances[account] -= amount;
        totalSupply -= amount;
    }
}
