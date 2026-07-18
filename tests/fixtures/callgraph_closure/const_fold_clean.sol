// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A pure compile-time-literal fold `(100 / 10) * 3`. Every source operand is a
// compile-time `Constant` - there is no runtime value being truncated, so this is
// NOT a precision bug and is NOT flagged. (The exact `100 / 10` keeps it an integer
// expression so it type-checks and survives to SlithIR as real DIVISION +
// MULTIPLICATION ops carrying Constant operands - which is exactly what the
// const-fold guard must skip.)
contract ConstFoldClean {
    function f() external pure returns (uint256) {
        uint256 r = (100 / 10) * 3;
        return r;
    }
}
