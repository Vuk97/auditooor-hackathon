// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MatchingEngineReduceOnlyOiAccountingGapVuln {
    uint256 public quoteOI;
    uint256 public constant MAX_OI = 1_000_000e18;

    struct Order { uint256 amount; bool reduceOnly; }

    function placeOrder(Order calldata order) external {
        quoteOI += order.amount;
        require(quoteOI <= MAX_OI, "MaxOI");
        _store(order);
    }

    function _store(Order calldata) internal pure {}
}
