// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousDaoForkThresholdClean {
    uint256 internal constant MAX_FORK_THRESHOLD = 2_000;
    uint256 internal forkThresholdBPSSetting;

    constructor() {
        forkThresholdBPSSetting = 2_000;
    }

    function forkThresholdBPS() external view returns (bool) {
        _checkForkThreshold();
        return forkThresholdBPSSetting > 1_500;
    }

    function _checkForkThreshold() internal view {
        require(forkThresholdBPSSetting <= MAX_FORK_THRESHOLD, "threshold out of range");
    }
}
