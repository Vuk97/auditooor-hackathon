// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but `kill` is gated behind an `onlyOwner` modifier so neither
/// a direct call nor a delegatecall-reached invocation from an arbitrary
/// caller can destroy the contract.
contract SelfDestructLogicClean {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function kill(address payable recipient) external onlyOwner {
        selfdestruct(recipient);
    }
}
