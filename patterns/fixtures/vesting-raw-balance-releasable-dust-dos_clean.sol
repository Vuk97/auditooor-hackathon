// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VestingRawBalanceReleasableDustDosClean {
    IERC20Like public immutable token;

    struct Schedule {
        uint64 start;
        uint64 duration;
        uint256 totalAllocated;
        uint256 claimed;
    }

    mapping(address => Schedule) public schedules;
    uint256 public accountedBalance;

    constructor(IERC20Like token_) {
        token = token_;
    }

    function releasable(address beneficiary) public view returns (uint256) {
        Schedule storage schedule = schedules[beneficiary];
        uint256 elapsed = block.timestamp - schedule.start;

        // CLEAN: release math is based on accounted allocation, not raw dust.
        uint256 vested = schedule.totalAllocated * elapsed / schedule.duration;
        return vested - schedule.claimed;
    }

    function rescueUnaccountedDust(address receiver) external {
        uint256 dust = token.balanceOf(address(this)) - accountedBalance;
        require(token.transfer(receiver, dust), "transfer failed");
    }
}
