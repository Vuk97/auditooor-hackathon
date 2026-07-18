// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library StableSwapMathFixture {
    uint256 internal constant AMP_PRECISION = 100;

    function target(uint256 _amplification, uint256 invariant) internal pure returns (uint256) {
        uint256 ampTimesCoins = _amplification * 2;
        return invariant * AMP_PRECISION / ampTimesCoins;
    }
}

contract StableswapAmpZeroConfigLivenessVuln {
    uint256 public constant MAX_AMP = 1_000_000;
    uint256 public constant MAX_AMP_MULTIPLIER = 10;
    uint256 public baseAmp;
    uint256 public nextAmp;

    error InvalidAmp();
    error ExcessiveAmpChange();

    constructor(uint256 _baseAmp) {
        if (_baseAmp >= MAX_AMP) revert InvalidAmp();
        baseAmp = _baseAmp * StableSwapMathFixture.AMP_PRECISION;
        nextAmp = baseAmp;
    }

    function quote(uint256 invariant) external view returns (uint256) {
        return StableSwapMathFixture.target(baseAmp, invariant);
    }

    function startAmpRamp(uint256 _nextAmp) external {
        uint256 scaledNextAmp = _nextAmp * StableSwapMathFixture.AMP_PRECISION;
        uint256 currentAmp = getCurrentAmp();
        if (scaledNextAmp > currentAmp * MAX_AMP_MULTIPLIER) revert ExcessiveAmpChange();
        nextAmp = scaledNextAmp;
    }

    function getCurrentAmp() public view returns (uint256) {
        return nextAmp;
    }
}
