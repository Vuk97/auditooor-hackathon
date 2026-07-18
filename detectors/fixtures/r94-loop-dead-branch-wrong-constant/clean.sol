// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract R94LoopDeadBranchWrongConstantClean {
    uint256 public matchedRoutes;
    uint256 public reachableBranchExecutions;

    function processRoutes(bool[] calldata active, bool[] calldata delayed) external returns (uint256) {
        require(active.length == delayed.length, "length mismatch");

        for (uint256 i = 0; i < active.length; ++i) {
            uint256 routeKind;
            if (delayed[i]) {
                routeKind = 2;
            } else if (active[i]) {
                routeKind = 0;
                matchedRoutes += 1;
            } else {
                routeKind = 1;
            }

            if (routeKind == 2) {
                reachableBranchExecutions += 1;
            }
        }

        return reachableBranchExecutions;
    }
}
