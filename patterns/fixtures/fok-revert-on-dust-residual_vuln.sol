// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MatchingVuln {
    uint256 public constant LOT_SIZE = 1e16;

    struct Order { uint256 size; uint256 filled; bool FOK; }

    function fillOrder(Order memory o, uint256 matched) external pure returns (uint256) {
        o.filled += matched;
        uint256 residual = o.size - o.filled;
        if (o.FOK) {
            // VULN: revert on any residual > 0, even sub-lot
            require(residual == 0, "FOK-residual");
        }
        return o.filled;
    }
}
