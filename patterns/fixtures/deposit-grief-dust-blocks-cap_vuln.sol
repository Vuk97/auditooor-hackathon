// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// deposit-grief-dust-blocks-cap detector. DO NOT DEPLOY.
///
/// The deposit function enforces a global cap via a running total but
/// imposes no minimum-deposit floor. An attacker can iterate 1-wei
/// deposits across unlimited fresh addresses to saturate `cap`, after
/// which every honest deposit reverts at the cap check.
contract DepositGriefVuln {
    uint256 public totalDeposited;
    uint256 public cap = 100_000_000e6; // 100M USDC-scale
    uint256 public maxDeposit = 10_000e6;

    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        // Cap enforcement — but no minimum-amount floor.
        require(totalDeposited + amount <= cap, "cap reached");

        totalDeposited += amount;
        balances[msg.sender] += amount;
    }

    function provide(uint256 amount) external {
        // Same shape on a second entry point.
        require(totalDeposited + amount <= cap, "maxTvl");
        totalDeposited += amount;
        balances[msg.sender] += amount;
    }
}
