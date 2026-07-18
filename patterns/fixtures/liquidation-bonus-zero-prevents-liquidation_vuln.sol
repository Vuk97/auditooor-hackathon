// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// liquidation-bonus-zero-prevents-liquidation detector. DO NOT DEPLOY.
///
/// The liquidation entry point scales the seize amount by `(100 + bonus)`
/// but never asserts `bonus > 0`. A newly listed market whose
/// `liquidationBonus` storage slot is still at its default of zero will
/// compute `seizeAmount == debt`, leaving no economic incentive for any
/// keeper to call `liquidate` — bad debt simply accumulates.
contract LendingVuln {
    // State var name matches the precondition regex
    //   liquidationBonus|bonusBps|bonus|liqBonus|incentive
    uint256 public liquidationBonus;

    struct Position {
        uint256 debt;
        uint256 collateral;
    }
    mapping(address => Position) public positions;

    constructor() {
        // VULN: liquidationBonus left at its default of zero. No setter
        // is required to reach the buggy state — the storage slot is
        // born at zero and the `liquidate` path will read it as-is.
    }

    // Seeds positions for the fixture so the function body references
    // the bonus arithmetic the detector keys on.
    function openPosition(uint256 debtAmt, uint256 collAmt) external {
        positions[msg.sender] = Position({debt: debtAmt, collateral: collAmt});
    }

    // VULN: the `(100 + liquidationBonus)` term uses the bonus variable
    // (matches body_contains_regex) but no require / revert gate asserts
    // it is nonzero (negative regex does NOT match → detector fires).
    function liquidate(address borrower) external returns (uint256 seizeAmount) {
        Position storage p = positions[borrower];
        // Canonical vulnerable shape: debt * (100 + bonus) / 100
        seizeAmount = (p.debt * (100 + liquidationBonus)) / 100;
        p.debt = 0;
        p.collateral -= seizeAmount;
    }
}
