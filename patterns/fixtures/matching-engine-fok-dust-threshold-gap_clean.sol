// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MatchingEngineFokDustThresholdGapClean {
    uint256 public constant LOT_SIZE = 1e16;

    struct Order { uint256 size; uint256 filled; bool FOK; }

    function fillOrder(Order memory order, uint256 matched) external pure returns (uint256) {
        order.filled += matched;
        uint256 residual = order.size - order.filled;
        if (order.FOK) {
            require(residual == 0 || residual < LOT_SIZE, "material residual");
        }
        return order.filled;
    }
}
