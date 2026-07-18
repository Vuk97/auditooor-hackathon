// SPDX-License-Identifier: MIT
// Fixture: liquidation-escape-uni-v3-zero-liquidity — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

contract LiquidationEscapeClean {
    struct Position {
        address owner;
        uint256 collateralValue;
        uint256 debt;
    }

    mapping(uint256 => Position) public positions;
    uint256 public liquidationThreshold = 110e16;

    function getCollateral(uint256 id) public view returns (uint256) {
        return positions[id].collateralValue;
    }

    // Refresh hooks — the fix idiom. Each liquidate* path MUST invoke one
    // before reading the positionValue / collateralValue for the threshold
    // comparison.
    function updateCollateral(uint256 id) public {
        // re-pricing hook: pull current Uni v3 liquidity and realised fees,
        // recompute positions[id].collateralValue in place.
        positions[id].collateralValue = _currentMarkValue(id);
    }

    function refreshPosition(uint256 id) public {
        positions[id].collateralValue = _currentMarkValue(id);
    }

    function getActiveLiquidity(uint256 id) public view returns (uint256) {
        return positions[id].collateralValue;
    }

    function _currentMarkValue(uint256 /*id*/) internal pure returns (uint256) {
        return 0;
    }

    // CLEAN: refreshes liquidity via updateCollateral before the threshold check.
    function liquidate(uint256 id) external {
        updateCollateral(id);
        Position storage p = positions[id];
        uint256 positionValue = getCollateral(id);
        require(positionValue * 1e18 < p.debt * liquidationThreshold, "healthy");
        p.collateralValue = 0;
        p.debt = 0;
    }

    // CLEAN: uses refreshPosition hook.
    function _liquidate(uint256 id) public {
        refreshPosition(id);
        require(positions[id].collateralValue < positions[id].debt, "healthy");
        positions[id].collateralValue = 0;
    }

    // CLEAN: re-evaluates via getActiveLiquidity.
    function liquidatePosition(uint256 id) external {
        uint256 live = getActiveLiquidity(id);
        require(live < positions[id].debt, "healthy");
        delete positions[id];
    }
}
