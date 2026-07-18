// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - timestamp-manipulation-umbrella
// CLEAN: all timestamp comparisons use >= (correct direction)
// and randomness uses an external verifiable source.

contract CleanTimestampLockup {
    mapping(address => uint256) public depositTime;
    mapping(address => uint256) public balance;
    uint256 public constant LOCK_PERIOD = 7 days;

    function deposit() external payable {
        depositTime[msg.sender] = block.timestamp;
        balance[msg.sender] += msg.value;
    }

    // CLEAN: >= comparison gives a window of time for the user to withdraw.
    function withdraw() external {
        uint256 unlockTime = depositTime[msg.sender] + LOCK_PERIOD;
        require(block.timestamp >= unlockTime, "still locked");
        uint256 amount = balance[msg.sender];
        balance[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

contract CleanVaultExit {
    mapping(address => uint256) public equity;
    uint256 public epochEnd;

    constructor(uint256 _epochEnd) {
        epochEnd = _epochEnd;
    }

    function deposit(uint256 amount) external {
        equity[msg.sender] += amount;
    }

    // CLEAN: exit allowed AFTER epoch ends (>= comparison).
    function exit() external {
        require(block.timestamp >= epochEnd, "epoch not yet over");
        uint256 amount = equity[msg.sender];
        equity[msg.sender] = 0;
        // transfer equity back
    }
}
