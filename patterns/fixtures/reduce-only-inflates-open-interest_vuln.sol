// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PerpsVuln {
    uint256 public quoteOI;
    uint256 public constant MAX_OI = 1_000_000e18;

    struct Order { uint256 amount; bool reduceOnly; }

    function placeOrder(Order calldata o) external {
        // VULN: reduce-only order still increments OI
        quoteOI += o.amount;
        require(quoteOI <= MAX_OI, "MaxOI");
    }
}
