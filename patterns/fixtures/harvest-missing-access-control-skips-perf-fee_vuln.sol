// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultVuln {
    uint256 public highWaterMark;
    uint256 public sharePrice;
    uint256 public perfFeesCollected;
    uint256 public constant PERF_FEE_BPS = 1000;

    // VULN: permissionless harvest lets anyone snapshot HWM
    function harvest() external {
        if (sharePrice > highWaterMark) {
            uint256 gain = sharePrice - highWaterMark;
            uint256 fee = (gain * PERF_FEE_BPS) / 10000;
            perfFeesCollected += fee;
            highWaterMark = sharePrice;
        }
    }

    function _setSharePrice(uint256 p) external { sharePrice = p; }
}
