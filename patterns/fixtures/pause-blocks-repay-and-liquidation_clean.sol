// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PauseRepayClean {
    bool public paused;
    address public owner;
    mapping(address => uint256) public debt;

    constructor() { owner = msg.sender; }

    modifier whenNotPaused() { require(!paused, "paused"); _; }

    function pause() external { require(msg.sender == owner); paused = true; }

    // Borrow is paused but repay/liquidate remain permissionless.
    function borrow(uint256 amount) external whenNotPaused {
        debt[msg.sender] += amount;
    }

    // Detector MUST NOT fire: no whenNotPaused modifier.
    function repay(uint256 amount) external {
        debt[msg.sender] -= amount;
    }

    function liquidate(address borrower, uint256 amount) external {
        debt[borrower] -= amount;
    }
}
