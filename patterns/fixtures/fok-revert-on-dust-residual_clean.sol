// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MatchingClean {
    uint256 public constant LOT_SIZE = 1e16;

    struct Order { uint256 size; uint256 filled; bool FOK; }

    function fillOrder(Order memory o, uint256 matched) external pure returns (uint256) {
        o.filled += matched;
        uint256 residual = o.size - o.filled;
        if (o.FOK) {
            require(residual < LOT_SIZE, "FOK-residual-above-lot");
        }
        return o.filled;
    }
}
