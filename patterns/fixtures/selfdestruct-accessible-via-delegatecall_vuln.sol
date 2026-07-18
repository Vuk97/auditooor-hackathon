// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// selfdestruct-accessible-via-delegatecall detector. DO NOT DEPLOY.
///
/// `kill` executes selfdestruct with no access-control modifier. The
/// contract is intended to be used as a delegatecall target (logic
/// implementation for a proxy), so leaving this entry point unprotected
/// both (a) allows anyone to destroy this contract directly and (b)
/// reproduces the parity-wallet class of incident when the attacker
/// reaches the same path via delegatecall from a fresh context.
contract SelfDestructLogicVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function kill(address payable recipient) external {
        // No onlyOwner / onlyAdmin / onlyRole — anyone can call this and
        // destroy the contract.
        selfdestruct(recipient);
    }
}
