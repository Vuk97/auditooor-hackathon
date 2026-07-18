// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// VULN: bare ERC20-style token that exposes approve() backed by an allowance
/// mapping WITHOUT any race-safe wrapper (no increaseAllowance,
/// decreaseAllowance, safeIncreaseAllowance, permit, or zero-reset inside
/// the body). Integrators who call approve() from a non-zero allowance to a
/// new non-zero value expose themselves to the classic ERC20 front-run race.
contract ApproveFrontrunVulnToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    // VULN: overwrites allowance with no zero-reset, no race-safe alternative.
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "ERC20: insufficient allowance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
