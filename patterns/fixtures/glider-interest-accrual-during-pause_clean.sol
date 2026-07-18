pragma solidity ^0.8.0;

contract LendingClean {
    bool public paused;
    uint256 public rate = 1e15;
    uint256 public debt;
    uint256 public lastAccrual;

    modifier whenNotPaused() { require(!paused, "paused"); _; }

    function repay(uint256 amt) external whenNotPaused {
        debt -= amt;
    }

    function borrow(uint256 amt) external whenNotPaused {
        debt += amt;
    }

    function accrueInterest() external whenNotPaused {
        uint256 dt = block.timestamp - lastAccrual;
        debt += debt * rate * dt / 1e18;
        lastAccrual = block.timestamp;
    }
}