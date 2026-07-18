// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract R94LoopDeadBranchWrongConstantPositive {
    uint256 public matchedRoutes;
    uint256 public deadBranchExecutions;

    function processRoutes(bool[] calldata active) external returns (uint256) {
        for (uint256 i = 0; i < active.length; ++i) {
            uint256 routeKind;
            if (active[i]) {
                routeKind = 0;
                matchedRoutes += 1;
            } else {
                routeKind = 1;
            }

            if (routeKind == 2) {
                deadBranchExecutions += 1;
            }
        }

        return deadBranchExecutions;
    }
}
