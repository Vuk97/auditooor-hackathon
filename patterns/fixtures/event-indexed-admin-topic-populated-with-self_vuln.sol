// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally incorrect test input for the
/// event-indexed-admin-topic-populated-with-self detector. DO NOT DEPLOY.
///
/// Mirrors Polymarket CTFExchange `Auth.sol` L84-89 (Cantina #46 Low).
/// `RemovedOperator` declares two indexed topics so off-chain dashboards
/// can attribute removals to the admin who performed them. The
/// renounce-self path passes `msg.sender` for both topics, destroying
/// the admin-attribution semantic.
contract AuthVuln {
    mapping(address => uint8) public admins;
    mapping(address => uint8) public operators;

    event RemovedOperator(address indexed removedOperator, address indexed admin);
    event RemovedAdmin(address indexed removedAdmin, address indexed admin);

    modifier onlyAdmin() {
        require(admins[msg.sender] == 1, "not admin");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender] == 1, "not operator");
        _;
    }

    /// Admin-driven removal — second topic correctly carries the actor.
    function removeOperator(address operator) external onlyAdmin {
        operators[operator] = 0;
        emit RemovedOperator(operator, msg.sender);
    }

    /// VULN: self-renounce reuses `RemovedOperator` and passes
    /// `msg.sender` for both topics. The `admin` topic now holds the
    /// renouncer, not the admin who authorized the removal.
    function renounceOperatorRole() external onlyOperator {
        operators[msg.sender] = 0;
        emit RemovedOperator(msg.sender, msg.sender);
    }

    /// VULN: same shape on the admin renounce path.
    function renounceAdminRole() external onlyAdmin {
        admins[msg.sender] = 0;
        emit RemovedAdmin(msg.sender, msg.sender);
    }
}
