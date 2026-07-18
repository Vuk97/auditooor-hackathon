// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VestingRawBalanceReleasableDustDosVuln {
    IERC20Like public immutable token;

    struct Schedule {
        uint64 start;
        uint64 duration;
        uint256 claimed;
    }

    mapping(address => Schedule) public schedules;

    constructor(IERC20Like token_) {
        token = token_;
    }

    function releasable(address beneficiary) public view returns (uint256) {
        Schedule storage schedule = schedules[beneficiary];
        uint256 elapsed = block.timestamp - schedule.start;

        // VULN: direct dust sent to this contract changes every schedule's
        // vested amount because raw custody balance is treated as allocation.
        uint256 vested = token.balanceOf(address(this)) * elapsed / schedule.duration;
        return vested - schedule.claimed;
    }

    function claim() external {
        uint256 amount = releasable(msg.sender);
        schedules[msg.sender].claimed += amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
