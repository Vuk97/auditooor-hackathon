// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — fixed variant of the liquidation-bonus-zero
/// pattern. The liquidate entry point asserts `liquidationBonus > 0`
/// before computing the seize amount, making the zero-bonus DoS
/// impossible by construction. The detector's negative regex anchor
/// (`require\s*\(\s*(liquidationBonus|bonus|incentive)\s*>\s*0`) DOES
/// match, so the detector does NOT fire.
contract LendingClean {
    uint256 public liquidationBonus;

    struct Position {
        uint256 debt;
        uint256 collateral;
    }
    mapping(address => Position) public positions;

    constructor(uint256 _bonus) {
        require(_bonus > 0, "bonus unset");
        liquidationBonus = _bonus;
    }

    function openPosition(uint256 debtAmt, uint256 collAmt) external {
        positions[msg.sender] = Position({debt: debtAmt, collateral: collAmt});
    }

    // CLEAN: the `require(liquidationBonus > 0, ...)` guard is the exact
    // idiom the detector's body_not_contains_regex anchor covers — with
    // the guard present, the not-contains predicate evaluates to FALSE
    // and the overall match fails. Detector stays silent.
    function liquidate(address borrower) external returns (uint256 seizeAmount) {
        require(liquidationBonus > 0, "bonus zero: no keeper profit");
        Position storage p = positions[borrower];
        seizeAmount = (p.debt * (100 + liquidationBonus)) / 100;
        p.debt = 0;
        p.collateral -= seizeAmount;
    }
}
