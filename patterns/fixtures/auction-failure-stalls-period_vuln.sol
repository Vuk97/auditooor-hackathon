// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuctionVuln {
    uint256 public period;
    uint256 public bidCount;

    function finalize() external {
        if (bidCount == 0) {
            // VULN: FAILED/UNDERSOLD path does not increment period
            return;
        }
        period += 1;
    }
}
