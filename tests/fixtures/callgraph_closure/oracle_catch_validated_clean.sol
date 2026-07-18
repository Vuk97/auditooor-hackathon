// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceFeed {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

/// The catch sets a fallback FLAG that a SUBSEQUENT require validates after the
/// try-merge - the failure is handled, not silently swallowed. -> NOT flagged.
contract OracleCatchValidated {
    IPriceFeed public feed;
    int256 public price;

    function refresh() external returns (uint256) {
        int256 p;
        bool ok = true;
        try feed.latestRoundData() returns (
            uint80,
            int256 _p,
            uint256,
            uint256,
            uint80
        ) {
            p = _p;
        } catch {
            ok = false;
        }
        require(ok, "oracle read failed");
        price = p;
        return uint256(price) * 1e18;
    }
}
