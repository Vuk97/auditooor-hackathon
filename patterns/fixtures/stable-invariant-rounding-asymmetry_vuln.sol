// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library FixedPoint {
    uint256 constant ONE = 1e18;
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * ONE) / b;
    }
    function divUp(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        return (a * ONE - 1) / b + 1;
    }
}

library StableMath {
    using FixedPoint for uint256;
    // VULN: join and exit use opposite rounding direction.
    function calcBptOutGivenExactTokensIn(uint256 amountIn, uint256 rate) internal pure returns (uint256) {
        return amountIn.divDown(rate);
    }
    function calcTokensOutGivenExactBptIn(uint256 bptIn, uint256 rate) internal pure returns (uint256) {
        return bptIn.divUp(rate);
    }
}

contract StableInvariantRoundingAsymmetryVuln {
    function join(uint256 amountIn, uint256 rate) external pure returns (uint256) {
        return StableMath.calcBptOutGivenExactTokensIn(amountIn, rate);
    }
    function exit(uint256 bptIn, uint256 rate) external pure returns (uint256) {
        return StableMath.calcTokensOutGivenExactBptIn(bptIn, rate);
    }
}
