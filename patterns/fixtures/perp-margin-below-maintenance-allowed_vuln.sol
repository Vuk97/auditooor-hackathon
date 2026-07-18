// SPDX-License-Identifier: MIT
// Fixture: perp-margin-below-maintenance-allowed — VULNERABLE
// Detector MUST fire on every function here.
pragma solidity ^0.8.20;

contract PerpMarginVuln {
    // Contract-level precondition: carries margin / leverage / imRatio state.
    mapping(address => uint256) public margin;
    mapping(address => uint256) public notional;
    uint256 public imRatio;
    uint256 public leverage;

    // NOTE: no maintenanceMargin / mmRatio / isHealthy / _checkHealth
    // anywhere in the contract. Every margin-moving path ships with no
    // post-update invariant.

    // VULN #1: openPosition — computes margin but never checks the
    // resulting ratio against a maintenance threshold.
    function openPosition(uint256 size, uint256 collateral) external {
        margin[msg.sender] += collateral;
        notional[msg.sender] += size;
        // (no maintenance check)
    }

    // VULN #2: increasePosition — grows notional without re-checking
    // margin ratio.
    function increasePosition(uint256 extraSize) external {
        notional[msg.sender] += extraSize;
        // margin/notional ratio can now be below maintenance.
    }

    // VULN #3: adjustMargin — lets caller pull collateral out without
    // verifying the post-withdrawal ratio.
    function adjustMargin(int256 delta) external {
        if (delta < 0) {
            margin[msg.sender] -= uint256(-delta);
        } else {
            margin[msg.sender] += uint256(delta);
        }
        // (no maintenance check — attacker can leave position immediately
        //  liquidatable)
    }

    // VULN #4: withdrawMargin — direct collateral withdrawal, no guard.
    function withdrawMargin(uint256 amount) external {
        margin[msg.sender] -= amount;
    }

    // VULN #5: changeLeverage — mutates leverage without reverting when
    // the implied margin ratio falls below maintenance.
    function changeLeverage(uint256 newLeverage) external {
        leverage = newLeverage;
    }

    // VULN #6: rebalance hook — recomputes ratio but does not enforce
    // the maintenance invariant.
    function rebalance(address trader) external {
        uint256 m = margin[trader];
        uint256 n = notional[trader];
        if (n > 0) {
            imRatio = (m * 1e18) / n;
        }
    }
}
