// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceFeed {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

/// A direct oracle read with NO try/catch at all - there is no swallow shape to
/// flag. -> NOT flagged.
contract OracleNoTry {
    IPriceFeed public feed;
    int256 public price;

    function refresh() external returns (uint256) {
        (, int256 p, , , ) = feed.latestRoundData();
        price = p;
        return uint256(price) * 1e18;
    }
}
