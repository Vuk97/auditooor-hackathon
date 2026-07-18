// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LimitOrderDirectionClean {
    uint256 internal direction;
    uint256 internal lastCancelledTick;

    constructor() {
        direction = 1;
    }

    function cancelAtDirectionTargetTick(int24 targetTick) external returns (bool) {
        uint256 orderDirection = direction;
        _checkTargetTick(orderDirection, targetTick);
        lastCancelledTick = uint256(uint24(targetTick));
        return orderDirection > 0;
    }

    function _checkTargetTick(uint256 orderDirection, int24 targetTick) internal pure {
        require(orderDirection > 0, "inactive");
        require(targetTick >= 0, "tick");
    }
}
