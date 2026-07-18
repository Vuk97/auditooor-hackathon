// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: approve path enforces the blocked registry.
contract TokenFreezeBypassApprovalSafe {
    mapping(address => bool) public blocked;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external {
        require(!blocked[msg.sender], "sender blocked");
        require(!blocked[spender], "spender blocked");
        allowance[msg.sender][spender] = amount;
    }

    function setBlocked(address a, bool v) external { blocked[a] = v; }
}
