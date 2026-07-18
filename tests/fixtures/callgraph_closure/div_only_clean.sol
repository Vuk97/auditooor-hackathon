// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A division whose result is NOT subsequently multiplied. There is no precision
// loss from a divide-before-multiply ordering here. NOT flagged.
contract DivOnlyClean {
    function share(uint256 amount, uint256 rate)
        external
        pure
        returns (uint256)
    {
        uint256 r = amount / rate;
        return r;
    }
}
