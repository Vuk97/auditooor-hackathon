// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RouterLiquidityClean {
    uint256 internal addRouterLiquidity;
    uint256 internal totalLiquidity;

    constructor() {
        addRouterLiquidity = 100;
        totalLiquidity = 100;
    }

    function removeRouterLiquidityFor(address router, uint256 amount) external returns (bool) {
        require(router != address(0), "router");
        uint256 available = addRouterLiquidity;
        _syncRouterAccounting(router, available);
        if (available < amount) {
            revert("amount");
        }
        _drain(router, amount);
        return totalLiquidity >= amount;
    }

    function _syncRouterAccounting(address, uint256 available) internal {
        totalLiquidity = available;
    }

    function _drain(address, uint256 amount) internal {
        totalLiquidity -= amount;
    }
}
