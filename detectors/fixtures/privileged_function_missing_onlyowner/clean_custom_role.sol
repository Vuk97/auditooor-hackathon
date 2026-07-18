// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// L-08 custom-role-variable clean fixture.
// All privileged mutating functions are guarded via inline require(msg.sender == <role>)
// or equivalent — NOT a named modifier.  The detector MUST NOT fire on any of them.
contract CustomRoleVarGuardedClean {
    address public owner;
    address public admin;
    address public operator;
    address public treasury;
    address public feeSink;

    constructor() {
        owner = msg.sender;
        admin = msg.sender;
        operator = msg.sender;
        treasury = msg.sender;
        feeSink = msg.sender;
    }

    // Reference modifier used elsewhere — precondition is met for the contract
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function rotateOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // Inline require(msg.sender == admin) — custom role variable guard
    function setTreasury(address newTreasury) external {
        require(msg.sender == admin, "not admin");
        treasury = newTreasury;
    }

    // Inline require(admin == msg.sender) — reversed operand order
    function setFeeSink(address newFeeSink) external {
        require(admin == msg.sender, "not admin");
        feeSink = newFeeSink;
    }

    // if (msg.sender != operator) revert style
    function updateOperator(address newOperator) external {
        if (msg.sender != operator) revert("not operator");
        operator = newOperator;
    }

    // _msgSender() == s_admin style (common in OZ meta-tx contexts)
    address private s_admin;
    function changeAdmin(address newAdmin) external {
        require(_msgSender() == s_admin, "not s_admin");
        s_admin = newAdmin;
    }

    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}
