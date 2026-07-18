// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LimitOrderDirectionPositive {
    uint256 internal direction;
    uint256 internal lastCancelledTick;

    constructor() {
        direction = 1;
    }

    function cancelAtDirectionTargetTick(int24 targetTick) external returns (bool) {
        uint256 orderDirection = direction;
        lastCancelledTick = uint256(uint24(targetTick));
        return orderDirection > 0;
    }
}
