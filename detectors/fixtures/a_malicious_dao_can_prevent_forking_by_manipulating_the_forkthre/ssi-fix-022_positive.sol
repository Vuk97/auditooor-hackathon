// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousDaoForkThresholdPositive {
    uint256 internal observations;
    uint256 internal forkThresholdBPSSetting;

    constructor() {
        forkThresholdBPSSetting = 10_000;
    }

    function forkThresholdBPS() external returns (bool) {
        observations += 1;
        return forkThresholdBPSSetting > 2_000;
    }
}
