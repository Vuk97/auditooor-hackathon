// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ClaimableAmountNotCheckpointedBeforePoolLeavePositive {
    mapping(address => uint256) public poolShares;
    mapping(address => uint256) public claimableAmount;
    uint256 public rewardPerShare;
    uint256 public totalPoolShares;

    function deposit(uint256 amount) external {
        _checkpointClaimable(msg.sender);
        poolShares[msg.sender] += amount;
        totalPoolShares += amount;
    }

    function leavePool(uint256 shares) external {
        require(poolShares[msg.sender] >= shares, "shares");
        poolShares[msg.sender] -= shares;
        totalPoolShares -= shares;
    }

    function _checkpointClaimable(address account) internal {
        claimableAmount[account] += (poolShares[account] * rewardPerShare) / 1e18;
    }

    function claim() external {
        _checkpointClaimable(msg.sender);
        uint256 amount = claimableAmount[msg.sender];
        claimableAmount[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
