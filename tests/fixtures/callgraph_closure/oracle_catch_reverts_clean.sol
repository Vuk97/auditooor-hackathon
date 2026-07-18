// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceFeed {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

/// The catch REVERTS (custom error) - the oracle failure is propagated, NOT
/// swallowed. -> NOT flagged.
contract OracleCatchReverts {
    IPriceFeed public feed;
    int256 public price;
    error OracleDown();

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
            revert OracleDown();
        }
        return uint256(price) * 1e18;
    }
}
