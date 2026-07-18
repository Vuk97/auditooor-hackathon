// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// VULN: AMM-style pool layers a commit-reveal deposit queue on top of
// Uniswap-v2-style reserves. The skim() function transfers every unit
// above `reserves0` to the caller, including the queued user deposits.
// An attacker back-running a pending deposit drains the user's funds.
contract PoolSkimVuln {
    IERC20 public token0;
    IERC20 public token1;

    // AMM-tracked reserves — updated only at reveal() time.
    uint256 public reserves0;
    uint256 public reserves1;

    // Pending deposit queue. Users transfer token0 in during commit();
    // the tokens sit on the pool above reserves until reveal() folds them
    // into reserves0. Intentionally NOT named pending/escrow/queued in the
    // skim() body so the detector can fire on the absence of the guard.
    mapping(address => uint256) public queuedDeposit;

    constructor(address _t0, address _t1) {
        token0 = IERC20(_t0);
        token1 = IERC20(_t1);
    }

    function commit(uint256 amount) external {
        token0.transferFrom(msg.sender, address(this), amount);
        queuedDeposit[msg.sender] += amount;
    }

    function reveal() external {
        uint256 amt = queuedDeposit[msg.sender];
        queuedDeposit[msg.sender] = 0;
        reserves0 += amt;
    }

    // BUG: classic v2 skim(), permissionless. Treats ALL balance-above-
    // reserves as surplus, including the queued user deposits sitting on
    // top of reserves awaiting reveal(). First caller drains them.
    function skim(address to) external {
        uint256 bal0 = token0.balanceOf(address(this));
        uint256 surplus0 = bal0 - reserves0;
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
