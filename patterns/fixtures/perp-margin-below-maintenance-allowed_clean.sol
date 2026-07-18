// SPDX-License-Identifier: MIT
// Fixture: perp-margin-below-maintenance-allowed — CLEAN
// Detector MUST NOT fire on any function here.
pragma solidity ^0.8.20;

contract PerpMarginClean {
    mapping(address => uint256) public margin;
    mapping(address => uint256) public notional;
    uint256 public imRatio;
    uint256 public leverage;
    uint256 public maintenanceMargin = 5e16; // 5% floor
    uint256 public mmRatio = 5e16;

    function _checkHealth(address trader) internal view {
        uint256 m = margin[trader];
        uint256 n = notional[trader];
        if (n == 0) return;
        uint256 ratio = (m * 1e18) / n;
        require(ratio >= maintenanceMargin, "below maintenance");
    }

    function isHealthy(address trader) public view returns (bool) {
        uint256 m = margin[trader];
        uint256 n = notional[trader];
        if (n == 0) return true;
        return (m * 1e18) / n >= mmRatio;
    }

    // CLEAN #1: openPosition calls _checkHealth at end.
    function openPosition(uint256 size, uint256 collateral) external {
        margin[msg.sender] += collateral;
        notional[msg.sender] += size;
        _checkHealth(msg.sender);
    }

    // CLEAN #2: increasePosition with maintenanceMargin guard.
    function increasePosition(uint256 extraSize) external {
        notional[msg.sender] += extraSize;
        uint256 ratio = (margin[msg.sender] * 1e18) / notional[msg.sender];
        require(ratio >= maintenanceMargin, "below mm");
    }

    // CLEAN #3: adjustMargin with post-write mmRatio check via helper.
    function adjustMargin(int256 delta) external {
        if (delta < 0) {
            margin[msg.sender] -= uint256(-delta);
        } else {
            margin[msg.sender] += uint256(delta);
        }
        require(isHealthy(msg.sender), "unhealthy");
    }

    // CLEAN #4: withdrawMargin with inline comparison.
    function withdrawMargin(uint256 amount) external {
        margin[msg.sender] -= amount;
        uint256 n = notional[msg.sender];
        if (n > 0) {
            uint256 marginRatio = (margin[msg.sender] * 1e18) / n;
            require(marginRatio >= mmRatio, "mm violation");
        }
    }

    // CLEAN #5: changeLeverage with maintenanceMargin reference.
    function changeLeverage(uint256 newLeverage) external {
        leverage = newLeverage;
        require(isHealthy(msg.sender), "maintenanceMargin breach");
    }

    // CLEAN #6: rebalance enforces mmRatio.
    function rebalance(address trader) external {
        uint256 m = margin[trader];
        uint256 n = notional[trader];
        if (n > 0) {
            imRatio = (m * 1e18) / n;
            require(imRatio >= mmRatio, "mm");
        }
    }
}
