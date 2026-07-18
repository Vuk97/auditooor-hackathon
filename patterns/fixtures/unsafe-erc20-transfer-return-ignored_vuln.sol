// SPDX-License-Identifier: MIT
// Fixture: unsafe-erc20-transfer-return-ignored — VULNERABLE
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract UnsafeTransferVuln {
    mapping(address => uint256) public balances;
    IERC20 public token;

    constructor(IERC20 t) { token = t; }

    // VULN: return value of transfer ignored; USDT-style tokens return false
    // silently and the withdraw path has already debited `balances`.
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    // VULN: transferFrom return ignored.
    function pull(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }

    // VULN: approve return ignored.
    function grantApproval(address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}
