// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PauseRepayVuln {
    bool public paused;
    address public owner;
    mapping(address => uint256) public debt;

    constructor() { owner = msg.sender; }

    modifier whenNotPaused() { require(!paused, "paused"); _; }

    function pause() external { require(msg.sender == owner); paused = true; }

    // Detector MUST fire: repay is gated on whenNotPaused.
    function repay(uint256 amount) external whenNotPaused {
        debt[msg.sender] -= amount;
    }

    // Detector MUST fire: liquidate is gated on whenNotPaused.
    function liquidate(address borrower, uint256 amount) external whenNotPaused {
        debt[borrower] -= amount;
    }
}
