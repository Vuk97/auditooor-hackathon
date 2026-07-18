// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Pausable {
    bool public paused;
    modifier whenNotPaused() { require(!paused, "paused"); _; }
    function _pause() internal { paused = true; }
}

contract StakingClean is Pausable {
    mapping(address => uint256) public pendingWithdraw;

    function stake() external payable whenNotPaused {
        pendingWithdraw[msg.sender] += msg.value;
    }

    function confirmWithdrawal(uint256 amount) external whenNotPaused {
        pendingWithdraw[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
