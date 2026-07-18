// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuctionClean {
    uint256 public period;
    uint256 public bidCount;
    event AuctionFailed(uint256 period);

    function finalize() external {
        if (bidCount == 0) {
            emit AuctionFailed(period);
            period += 1; // CLEAN: advance anyway
            return;
        }
        period += 1;
    }
}
