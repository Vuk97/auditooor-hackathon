// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CLOBVuln {
    mapping(address => bool) public isOperator;
    mapping(address => mapping(address => bool)) public operatorApprovals;
    address public admin;
    constructor() { admin = msg.sender; }

    /// VULN: disallowOperator clears the global flag but leaves per-user approvals.
    function disallowOperator(address op) external {
        require(msg.sender == admin, "not admin");
        isOperator[op] = false;
    }

    function approveOperator(address op) external { operatorApprovals[msg.sender][op] = true; }

    function placeOrder(address user) external {
        require(operatorApprovals[user][msg.sender], "not approved");
        // executes on behalf of user
    }
}
