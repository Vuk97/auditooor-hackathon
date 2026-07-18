// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultClean {
    uint256 public highWaterMark;
    uint256 public sharePrice;
    uint256 public perfFeesCollected;
    uint256 public constant PERF_FEE_BPS = 1000;
    address public keeper;
    address public owner;

    modifier onlyKeeper() { require(msg.sender == keeper || msg.sender == owner, "not keeper"); _; }

    function harvest() external onlyKeeper {
        if (sharePrice > highWaterMark) {
            uint256 gain = sharePrice - highWaterMark;
            uint256 fee = (gain * PERF_FEE_BPS) / 10000;
            perfFeesCollected += fee;
            highWaterMark = sharePrice;
        }
    }

    function _setSharePrice(uint256 p) external { sharePrice = p; }
}
