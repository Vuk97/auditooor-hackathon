// SPDX-License-Identifier: MIT
// Fixture: liquidation-escape-uni-v3-zero-liquidity — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract LiquidationEscapeVuln {
    struct Position {
        address owner;
        uint256 collateralValue; // cached — never refreshed before liquidation check
        uint256 debt;
    }

    mapping(uint256 => Position) public positions;
    uint256 public liquidationThreshold = 110e16; // 110%

    function getPosition(uint256 id) external view returns (Position memory) {
        return positions[id];
    }

    function getCollateral(uint256 id) public view returns (uint256) {
        return positions[id].collateralValue;
    }

    // VULN: reads cached collateralValue / getCollateral but never calls
    // updateCollateral / refreshPosition / getActiveLiquidity to pull the
    // current underlying liquidity. Borrower can escape by depositing a
    // zero-liquidity Uni v3 NFT or by withdrawing realised LP fees.
    function liquidate(uint256 id) external {
        Position storage p = positions[id];
        uint256 positionValue = getCollateral(id);
        require(positionValue * 1e18 < p.debt * liquidationThreshold, "healthy");
        // seize …
        p.collateralValue = 0;
        p.debt = 0;
    }

    // VULN: same shape in a public variant.
    function _liquidate(uint256 id) public {
        require(positions[id].collateralValue < positions[id].debt, "healthy");
        positions[id].collateralValue = 0;
    }

    // VULN: third variant with the getPosition read path.
    function liquidatePosition(uint256 id) external {
        Position memory snap = positions[id];
        require(snap.collateralValue < snap.debt, "healthy");
        delete positions[id];
    }
}
