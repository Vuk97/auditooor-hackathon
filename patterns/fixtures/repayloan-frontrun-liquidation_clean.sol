// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RepayFrontrunClean {
    struct Position {
        uint256 debt;
        uint256 collateral;
        bool liquidated;
    }

    mapping(address => Position) public positions;

    // Satisfies contract-level precondition (liquidate function exists).
    function liquidate(address borrower) external {
        Position storage p = positions[borrower];
        p.liquidated = true;
        p.collateral = 0;
    }

    // CLEAN: repayLoan does NOT guard on `liquidated` / `healthy` / `active`
    // state. Partial repay against outstanding debt is always permitted,
    // even for positions in the process of being liquidated, which removes
    // the frontrunning incentive. Detector must NOT fire — the
    // `function.body_contains_regex` positive anchor on a liquidat/active/
    // healthy require() fails to match.
    function repayLoan(uint256 amount) external {
        Position storage p = positions[msg.sender];
        if (amount > p.debt) amount = p.debt;
        p.debt -= amount;
    }
}
