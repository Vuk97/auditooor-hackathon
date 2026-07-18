// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// CLEAN: the commit-reveal queue is tracked in an explicit running total
// (`totalPending0`) and skim() subtracts it from the surplus before
// transferring. The queued user deposits remain honoured after skim.
contract PoolSkimClean {
    IERC20 public token0;
    IERC20 public token1;

    uint256 public reserves0;
    uint256 public reserves1;

    mapping(address => uint256) public queuedDeposit;
    // Running sum of outstanding user deposits awaiting reveal. Maintained
    // at every commit / reveal / cancel so the skim() guard is O(1).
    uint256 public totalPending0;

    constructor(address _t0, address _t1) {
        token0 = IERC20(_t0);
        token1 = IERC20(_t1);
    }

    function commit(uint256 amount) external {
        token0.transferFrom(msg.sender, address(this), amount);
        queuedDeposit[msg.sender] += amount;
        totalPending0 += amount;
    }

    function reveal() external {
        uint256 amt = queuedDeposit[msg.sender];
        queuedDeposit[msg.sender] = 0;
        totalPending0 -= amt;
        reserves0 += amt;
    }

    // FIX: subtract the outstanding pending-deposit total before computing
    // the surplus. Only true unaccounted surplus is sent to `to`.
    function skim(address to) external {
        uint256 bal0 = token0.balanceOf(address(this));
        // Reserved for pending user deposits awaiting reveal.
        uint256 reserved0 = totalPending0;
        uint256 surplus0 = bal0 - reserves0 - reserved0;
        if (surplus0 > 0) {
            token0.transfer(to, surplus0);
        }
        uint256 bal1 = token1.balanceOf(address(this));
        uint256 surplus1 = bal1 - reserves1;
        if (surplus1 > 0) {
            token1.transfer(to, surplus1);
        }
    }
}
