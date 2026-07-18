// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function swap(uint256 amountIn, uint256 minOut) external returns (uint256);
}

contract HarvesterVuln {
    address public AUTOMATE; // Gelato Automate contract
    address public pool;

    constructor(address _automate, address _pool) {
        AUTOMATE = _automate;
        pool = _pool;
    }

    // VULN: gating on msg.sender == AUTOMATE is equivalent to no guard
    // because Automate.createTask is permissionless. Attacker supplies
    // minimumAmountOut = 1 and sandwiches.
    function harvest(address yieldToken, uint256 minimumAmountOut) external returns (uint256 out) {
        require(msg.sender == AUTOMATE, "not gelato");
        yieldToken; // silence
        out = ICurvePool(pool).swap(1e18, minimumAmountOut);
    }
}
