// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — correct shape. The renounce path either
/// uses a dedicated `RenouncedOperatorRole(address indexed operator)`
/// event, or emits `address(0)` in the actor topic so off-chain
/// indexers can filter the no-admin case. Either resolution preserves
/// the admin-attribution semantic of the two-indexed-topic event.
contract AuthClean {
    mapping(address => uint8) public admins;
    mapping(address => uint8) public operators;
    mapping(address => address) public adminOf; // who granted each operator

    event RemovedOperator(address indexed removedOperator, address indexed admin);
    event RemovedAdmin(address indexed removedAdmin, address indexed admin);
    event RenouncedOperatorRole(address indexed operator);
    event RenouncedAdminRole(address indexed admin);

    modifier onlyAdmin() {
        require(admins[msg.sender] == 1, "not admin");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender] == 1, "not operator");
        _;
    }

    function removeOperator(address operator) external onlyAdmin {
        operators[operator] = 0;
        emit RemovedOperator(operator, msg.sender);
    }

    /// CLEAN: distinct event for the self-renounce path. Off-chain
    /// consumers disambiguate by event signature, no topic collision.
    function renounceOperatorRole() external onlyOperator {
        operators[msg.sender] = 0;
        emit RenouncedOperatorRole(msg.sender);
    }

    /// CLEAN: distinct event for the admin self-renounce path.
    function renounceAdminRole() external onlyAdmin {
        admins[msg.sender] = 0;
        emit RenouncedAdminRole(msg.sender);
    }
}
