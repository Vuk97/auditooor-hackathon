// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract DistributorVuln {
    address public quoteToken;
    uint256 public rewardBucket;

    // VULN: takes arbitrary token but credits the canonical reward accumulator
    function donate(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        rewardBucket += amount;
    }

    function claim(uint256 share) external {
        uint256 payout = (rewardBucket * share) / 1e18;
        rewardBucket -= payout;
        IERC20(quoteToken).transfer(msg.sender, payout);
    }
}
