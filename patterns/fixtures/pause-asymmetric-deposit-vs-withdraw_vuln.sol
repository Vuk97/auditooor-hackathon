// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Pausable {
    bool public paused;
    modifier whenNotPaused() { require(!paused, "paused"); _; }
    function _pause() internal { paused = true; }
}

contract StakingVuln is Pausable {
    mapping(address => uint256) public pendingWithdraw;

    function stake() external payable whenNotPaused {
        pendingWithdraw[msg.sender] += msg.value;
    }

    // VULN: confirmWithdrawal has no whenNotPaused
    function confirmWithdrawal(uint256 amount) external {
        pendingWithdraw[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
