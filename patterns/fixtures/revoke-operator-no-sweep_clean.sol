// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CLOBClean {
    mapping(address => bool) public isOperator;
    mapping(address => mapping(address => bool)) public operatorApprovals;
    mapping(address => address[]) internal _approversOf;
    address public admin;
    constructor() { admin = msg.sender; }

    /// CLEAN: sweeps per-user approvalss on global revoke.
    function disallowOperator(address op) external {
        require(msg.sender == admin, "not admin");
        isOperator[op] = false;
        address[] storage ap = _approversOf[op];
        for (uint256 i = 0; i < ap.length; i++) {
            operatorApprovals[ap[i]][op] = false;
        }
        delete _approversOf[op];
    }
}
