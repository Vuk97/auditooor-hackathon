// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaugeKillVuln {
    bool public isAlive = true;
    uint256 public pendingRewards;
    address public admin;

    // VULN: flips isAlive without flushing pendingRewards to LPs.
    function killGauge() external {
        require(msg.sender == admin, "not admin");
        isAlive = false;
    }
}
