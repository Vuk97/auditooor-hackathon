// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4 FP-fix #1): a DIRECT external VIEW call (STATICCALL) THEN a state-write
// within ONE function. A view call CANNOT reenter-and-write, so the write after it is
// CEI-SAFE -> NOT flagged. Pins that the CEI oracle counts only STATE-MUTATING
// external calls (the legacy coarse `_node_is_external_call` wrongly flagged this).
interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract CeiViewCallThenWriteClean {
    IPriceOracle public oracle;
    uint256 public lastPrice;

    function update() external {
        uint256 p = oracle.getPrice();   // external VIEW call -> STATICCALL, cannot reenter
        lastPrice = p;                   // state-write AFTER a view call: CEI-SAFE
    }
}
