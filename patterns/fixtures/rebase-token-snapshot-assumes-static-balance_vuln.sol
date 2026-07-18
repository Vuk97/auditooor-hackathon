// SPDX-License-Identifier: MIT
// Fixture: rebase-token-snapshot-assumes-static-balance — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IStETH {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract RebaseVault {
    IStETH public stETH;
    mapping(address => uint256) public deposited; // VULN: raw balance snapshot
    uint256 public totalDeposited;

    // VULN: stores stETH.balanceOf snapshot, no principal / shares tracking.
    // Between now and withdraw, stETH rebases and `deposited` no longer
    // matches the vault's true holdings → accounting drift.
    function deposit(uint256 amount) external {
        stETH.transferFrom(msg.sender, address(this), amount);
        uint256 snap = stETH.balanceOf(address(this));
        deposited[msg.sender] = snap;       // writes `deposited`
        totalDeposited += amount;
    }

    function withdraw() external {
        // Comparing raw snapshot against current balanceOf — will drift.
        require(deposited[msg.sender] > 0, "none");
        uint256 current = stETH.balanceOf(address(this));
        require(current >= deposited[msg.sender], "rebased down");
        deposited[msg.sender] = 0;
    }
}
