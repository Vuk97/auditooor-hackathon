// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceFeed {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

/// The catch does NOT revert inline - it calls a ONE-HOP INTERNAL helper
/// `_fail()` whose body UNCONDITIONALLY reverts (custom error). The whole tx
/// reverts on a feed failure, so this is NOT a swallow. The behavior is
/// equivalent to `oracle_catch_reverts_clean.sol`'s inline `revert OracleDown()`,
/// but the propagation is one hop away through an internal call. -> NOT flagged.
/// (Regression for the W2 transitive-propagate false-positive fix.)
contract OracleCatchHelperReverts {
    IPriceFeed public feed;
    int256 public price;
    error OracleDown();

    function _fail() internal pure {
        revert OracleDown();
    }

    function refresh() external returns (uint256) {
        try feed.latestRoundData() returns (
            uint80,
            int256 p,
            uint256,
            uint256,
            uint80
        ) {
            price = p;
        } catch {
            _fail();
        }
        return uint256(price) * 1e18;
    }
}

/// Library-revert variant: the catch propagates via a library function whose
/// body unconditionally reverts. Behavior-equivalent to an inline revert. ->
/// NOT flagged.
library Errors {
    error Stale();

    function revertOnStale() internal pure {
        revert Stale();
    }
}

contract OracleCatchLibraryReverts {
    IPriceFeed public feed;
    int256 public price;

    function refresh() external returns (uint256) {
        try feed.latestRoundData() returns (
            uint80,
            int256 p,
            uint256,
            uint256,
            uint80
        ) {
            price = p;
        } catch {
            Errors.revertOnStale();
        }
        return uint256(price) * 1e18;
    }
}
