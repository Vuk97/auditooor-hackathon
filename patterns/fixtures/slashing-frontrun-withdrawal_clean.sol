// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the
/// vuln fixture, but `slash` extends the penalty to the
/// `pendingWithdrawals` bucket, so a withdrawal-frontrun cannot let
/// the operator escape the slash.
contract SlasherClean {
    address public owner;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public withdrawReadyAt;

    uint256 public constant WITHDRAW_DELAY = 7 days;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function stake() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        pendingWithdrawals[msg.sender] += amount;
        withdrawReadyAt[msg.sender] = block.timestamp + WITHDRAW_DELAY;
    }

    function slash(address operator, uint256 amount) external onlyOwner {
        // Retrospectively penalizes the pendingWithdrawals bucket so a
        // mempool frontrun via `withdraw` cannot save the operator.
        uint256 active = balances[operator];
        uint256 pending = pendingWithdrawals[operator];

        if (amount <= active) {
            balances[operator] = active - amount;
        } else {
            uint256 remainder = amount - active;
            balances[operator] = 0;
            require(pending >= remainder, "over-slash");
            pendingWithdrawals[operator] = pending - remainder;
        }
    }

    function applySlash(address operator, uint256 amount) external onlyOwner {
        // Same retrospective-drain logic on a second entry point.
        pendingWithdrawals[operator] -= (amount / 2);
        balances[operator] -= (amount / 2);
    }
}
