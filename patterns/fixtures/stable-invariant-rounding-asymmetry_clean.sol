// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library FixedPoint {
    uint256 constant ONE = 1e18;
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * ONE) / b;
    }
}

library StableMath {
    using FixedPoint for uint256;
    // CLEAN: both directions round DOWN — user always loses dust to protocol.
    function calcBptOutGivenExactTokensIn(uint256 amountIn, uint256 rate) internal pure returns (uint256) {
        return amountIn.divDown(rate);
    }
    function calcTokensOutGivenExactBptIn(uint256 bptIn, uint256 rate) internal pure returns (uint256) {
        return bptIn.divDown(rate);
    }
}

contract StableInvariantRoundingAsymmetryClean {
    function settleJoin(uint256 amountIn, uint256 rate) external returns (uint256 bpt) {
        bpt = StableMath.calcBptOutGivenExactTokensIn(amountIn, rate);
    }
    function settleExit(uint256 bptIn, uint256 rate) external returns (uint256 out) {
        out = StableMath.calcTokensOutGivenExactBptIn(bptIn, rate);
    }
}
