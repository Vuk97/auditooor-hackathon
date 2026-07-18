// SPDX-License-Identifier: MIT
// Fixture for the AST-exact call-site selector (Glider gap #4).
//
// `validateExit` is the TARGET guard. It is reachable from FIVE distinct
// call-site shapes (direct / alias / overload / virtual-override / interface).
// A grep enumerator keyed on the target's canonical owner cannot resolve the
// alias, the overload-by-signature, the virtual-override, or the interface
// dispatch.
pragma solidity ^0.8.0;

library ExitLib {
    // The TARGET guard (overload #1: single arg).
    function validateExit(uint256 leafId) internal pure returns (bool) {
        return leafId != 0;
    }

    // Overload #2: same name, DIFFERENT signature. A name-only grep cannot tell
    // this apart from overload #1 -> it cannot enumerate per-signature sites.
    function validateExit(uint256 leafId, address to) internal pure returns (bool) {
        return leafId != 0 && to != address(0);
    }
}

interface IExitGuard {
    function validateExit(uint256 leafId) external view returns (bool);
}

// Concrete impl of the interface guard -- the interface dispatch resolves here.
contract ExitGuardImpl is IExitGuard {
    function validateExit(uint256 leafId) external pure override returns (bool) {
        return leafId != 0;
    }
}
