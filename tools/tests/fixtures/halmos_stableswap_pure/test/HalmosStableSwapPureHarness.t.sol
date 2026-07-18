// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library StableSwapMathPureFixture {
    uint256 internal constant AMP_PRECISION = 100;
    uint256 internal constant N_COINS = 2;
    uint256 internal constant MAX_AMP = 1_000_000;

    function acceptsRawAmp(uint256 rawAmp) internal pure returns (bool) {
        return rawAmp > 0 && rawAmp < MAX_AMP;
    }

    function scaleRawAmp(uint256 rawAmp) internal pure returns (uint256) {
        require(acceptsRawAmp(rawAmp), "invalid amp");
        return rawAmp * AMP_PRECISION;
    }

    function quoteFromRawAmp(uint256 rawAmp, uint256 invariant) internal pure returns (uint256) {
        uint256 scaledAmp = scaleRawAmp(rawAmp);
        return invariant * AMP_PRECISION / (scaledAmp * N_COINS);
    }
}

contract HalmosStableSwapPureHarness {
    function test_concreteStableSwapPureChecks() external pure {
        assert(StableSwapMathPureFixture.acceptsRawAmp(1));
        assert(!StableSwapMathPureFixture.acceptsRawAmp(0));
        assert(!StableSwapMathPureFixture.acceptsRawAmp(StableSwapMathPureFixture.MAX_AMP));
        assert(StableSwapMathPureFixture.quoteFromRawAmp(50, 10_000) == 100);
    }

    function check_validAmpAlwaysHasNonZeroDenominator(uint256 rawAmp) external pure {
        require(StableSwapMathPureFixture.acceptsRawAmp(rawAmp));

        uint256 scaledAmp = StableSwapMathPureFixture.scaleRawAmp(rawAmp);
        uint256 denominator = scaledAmp * StableSwapMathPureFixture.N_COINS;

        assert(denominator != 0);
    }

    function check_quoteMatchesReducedFormula() external pure {
        uint256 rawAmp = 50;
        uint256 invariant = 10_000;

        uint256 quote = StableSwapMathPureFixture.quoteFromRawAmp(rawAmp, invariant);
        uint256 reduced = invariant / (rawAmp * StableSwapMathPureFixture.N_COINS);

        assert(quote == reduced);
    }

    function check_zeroAmpRejectedBeforeDivision(uint128 invariant) external pure {
        assert(!StableSwapMathPureFixture.acceptsRawAmp(0));

        if (invariant > 0) {
            assert(invariant / StableSwapMathPureFixture.AMP_PRECISION >= 0);
        }
    }
}
