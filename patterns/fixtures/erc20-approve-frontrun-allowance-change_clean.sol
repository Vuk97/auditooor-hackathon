// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// CLEAN: token exposes race-safe wrappers (increaseAllowance /
/// decreaseAllowance) AND its approve() body mentions the safe path, so the
/// pattern's negative regex fires on "increaseAllowance" / "decreaseAllowance"
/// and the detector does NOT flag the implementation.
contract ApproveFrontrunCleanToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// Callers should prefer increaseAllowance / decreaseAllowance to avoid
    /// the well-known approve-race. See EIP-20 and OpenZeppelin's ERC20.
    function approve(address spender, uint256 amount) external returns (bool) {
        // Reference the safe wrappers so the implementation's intent is
        // visible in the body (and the negative regex in the DSL matches).
        // increaseAllowance / decreaseAllowance exist on this contract.
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 added) external returns (bool) {
        allowance[msg.sender][spender] += added;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 sub) external returns (bool) {
        uint256 cur = allowance[msg.sender][spender];
        require(cur >= sub, "ERC20: decrease below zero");
        allowance[msg.sender][spender] = cur - sub;
        emit Approval(msg.sender, spender, cur - sub);
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
