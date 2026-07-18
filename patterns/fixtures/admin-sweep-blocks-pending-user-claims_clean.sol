// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// CLEAN: sweep() subtracts the total pending user rewards before
// transferring, so all accrued claims remain honourable after the sweep.
contract StakingRewardsClean {
    address public owner;
    IERC20 public rewardToken;

    mapping(address => uint256) public pendingReward;
    // Running total of pending user claims, maintained at every
    // accrue/claim so the sweep guard is O(1).
    uint256 public totalPending;

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
        totalPending += amount;
    }

    function claim() external {
        uint256 amt = pendingReward[msg.sender];
        pendingReward[msg.sender] = 0;
        totalPending -= amt;
        rewardToken.transfer(msg.sender, amt);
    }

    // FIX: reserve the outstanding pending-claims total; only the
    // surplus above it is sweepable.
    function sweep(address to, uint256 amount) external onlyOwner {
        uint256 bal = rewardToken.balanceOf(address(this));
        uint256 reserved = totalPending;
        require(bal >= reserved + amount, "would strand pending claims");
        rewardToken.transfer(to, amount);
    }
}
