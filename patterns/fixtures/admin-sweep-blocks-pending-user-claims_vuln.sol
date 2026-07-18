// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// VULN: sweep() moves the entire reward-token balance out of the
// contract without subtracting the sum of pending user rewards. Every
// subsequent user claim reverts on insufficient-balance.
contract StakingRewardsVuln {
    address public owner;
    IERC20 public rewardToken;

    // Per-user accrued-but-unclaimed reward (pending claim).
    mapping(address => uint256) public pendingReward;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _rewardToken) {
        owner = msg.sender;
        rewardToken = IERC20(_rewardToken);
    }

    function accrue(address user, uint256 amount) external {
        pendingReward[user] += amount;
    }

    function claim() external {
        uint256 amt = pendingReward[msg.sender];
        pendingReward[msg.sender] = 0;
        rewardToken.transfer(msg.sender, amt);
    }

    // BUG: full balance sweep — no pending-reserve guard. Admin pulls
    // the entire balance and strands every pending claim.
    function sweep(address to) external onlyOwner {
        uint256 bal = rewardToken.balanceOf(address(this));
        rewardToken.transfer(to, bal);
    }
}
