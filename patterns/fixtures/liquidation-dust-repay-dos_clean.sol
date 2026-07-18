// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LiquidationDustDosClean {
    struct Position {
        uint256 debt;
        uint256 collateral;
        uint256 shares;
    }

    mapping(address => Position) public positions;

    function burnOneShare() external {
        Position storage p = positions[msg.sender];
        if (p.shares > 0) {
            p.shares -= 1;
        }
    }

    // CLEAN: liquidate() accepts shares == 0 as a graceful no-op and
    // always seizes whatever collateral remains. No strict positive gate,
    // so the dust-repay DoS is impossible. The detector's
    // `function.body_contains_regex` positive anchor on a
    // `shares|debt|borrow|amount > 0 / != 0 / == amount` require() fails
    // to match and the detector does NOT fire.
    function liquidate(address borrower, uint256 amount) external {
        Position storage p = positions[borrower];
        if (p.shares == 0 && p.collateral == 0) {
            return; // nothing to seize — graceful no-op, not a revert
        }
        if (amount > p.debt) amount = p.debt;
        p.debt -= amount;
        p.shares = 0;
    }
}
