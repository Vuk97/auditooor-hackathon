// SPDX-License-Identifier: MIT
// Fixture: borrow-can-drain-protocol-reserves — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// VULNERABLE: borrow() checks debtSharesTotal <= totalLent but does NOT
// subtract reserves from the balance first. The protocol safety cushion
// (reserves) can be drained by a well-collateralized borrower.
contract LendingVaultVuln {
    uint256 public totalLent;
    uint256 public totalDeposited;
    uint256 public reserves;         // protocol safety cushion
    uint256 public debtSharesTotal;

    address public underlying;
    address public owner;

    // VULN: reserves are not subtracted from balance before the cap check.
    // An attacker can borrow up to totalLent (including the reserve cushion).
    function borrow(uint256 shares) external {
        // debtSharesTotal > totalLent pattern matched by detector
        require(debtSharesTotal + shares <= totalLent, "cap reached");
        // Missing: available = balance - reserves check
        // reserves can be drained via a well-collateralized borrow

        debtSharesTotal += shares;
        IERC20(underlying).transfer(msg.sender, shares);
    }
}
