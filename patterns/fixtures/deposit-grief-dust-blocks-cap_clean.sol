// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the
/// vuln fixture, but each deposit entry-point enforces an explicit
/// minimum-deposit floor that prevents dust-grief saturation of the cap.
contract DepositGriefClean {
    uint256 public totalDeposited;
    uint256 public cap = 100_000_000e6;
    uint256 public constant MIN_DEPOSIT = 100e6; // 100 USDC floor

    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        require(amount >= MIN_DEPOSIT, "dust");
        require(totalDeposited + amount <= cap, "cap reached");

        totalDeposited += amount;
        balances[msg.sender] += amount;
    }

    function provide(uint256 amount) external {
        require(amount >= MIN_DEPOSIT, "dust");
        require(totalDeposited + amount <= cap, "maxTvl");
        totalDeposited += amount;
        balances[msg.sender] += amount;
    }
}
