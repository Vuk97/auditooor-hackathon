// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - timestamp-manipulation-umbrella
// VULN A: equality check on deadline (one-block window - locked if missed)
// VULN B: block.timestamp used as pseudo-randomness seed
// VULN C: vault exit gated with wrong-direction timestamp check

contract VulnTimestampLockup {
    mapping(address => uint256) public depositTime;
    mapping(address => uint256) public balance;
    uint256 public constant LOCK_PERIOD = 7 days;

    function deposit() external payable {
        depositTime[msg.sender] = block.timestamp;
        balance[msg.sender] += msg.value;
    }

    // VULN A: exact equality check - window is exactly one block wide.
    // If the user misses block N, funds are permanently locked.
    function withdraw() external {
        uint256 unlockTime = depositTime[msg.sender] + LOCK_PERIOD;
        // BUG: should be >= not ==
        require(block.timestamp == unlockTime, "not unlock time");
        uint256 amount = balance[msg.sender];
        balance[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

contract VulnTimestampRandomness {
    uint256 public jackpot;
    mapping(address => uint256) public tickets;

    function buyTicket() external payable {
        tickets[msg.sender] += msg.value;
        jackpot += msg.value;
    }

    // VULN B: block.timestamp used as randomness - miner/validator manipulable
    function claimJackpot() external {
        // BUG: validator knows block.timestamp; can selectively include tx
        uint256 seed = uint(block.timestamp) % 100;
        require(seed < 5, "not a winner");
        uint256 prize = jackpot;
        jackpot = 0;
        payable(msg.sender).transfer(prize);
    }
}

contract VulnVaultExit {
    mapping(address => uint256) public equity;
    uint256 public epochEnd;

    constructor(uint256 _epochEnd) {
        epochEnd = _epochEnd;
    }

    function deposit(uint256 amount) external {
        equity[msg.sender] += amount;
    }

    // VULN C: vault exit locked - wrong direction timestamp check
    // block.timestamp <= epochEnd means exit is ONLY allowed during the epoch, not after.
    // Users trying to exit after epoch ends are permanently blocked.
    function exit() external {
        require(block.timestamp <= epochEnd, "epoch over: equity locked");
        uint256 amount = equity[msg.sender];
        equity[msg.sender] = 0;
        // transfer equity back
    }
}
