// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardDistVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public rewardPerShare; // scaled 1e18

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // BUG: snapshots totalSupply() before _mint, then divides fee by stale total.
    function deposit(uint256 amount) external {
        uint256 fee = (amount * 200) / 10_000; // 2% fee
        uint256 tsBefore = totalSupply; // STALE SNAPSHOT
        _mint(msg.sender, amount - fee);
        if (tsBefore > 0) {
            rewardPerShare += (fee * 1e18) / tsBefore; // divided by pre-mint total
        }
    }
}
