// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: burnFrom() rejects address(0) as the `account` parameter
// before touching balance or totalSupply storage. Matches the
// OpenZeppelin ERC20._burn convention.
contract TokenClean {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "to is zero");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // FIX: explicit zero-address guard at the top of the entry point.
    // The body regex in the DSL pattern filters this out as a valid
    // guard via `require\s*\(.*!=\s*address\s*\(\s*0`.
    function burnFrom(address account, uint256 amount) external {
        require(account != address(0), "ERC20: burn from zero address");
        uint256 allowed = allowance[account][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[account][msg.sender] = allowed - amount;
        }
        balances[account] -= amount;
        totalSupply -= amount;
    }
}
