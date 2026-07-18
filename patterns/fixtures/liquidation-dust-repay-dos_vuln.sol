// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LiquidationDustDosVuln {
    struct Position {
        uint256 debt;
        uint256 collateral;
        uint256 shares;
    }

    mapping(address => Position) public positions;

    // A borrower-callable function that lets the borrower shave 1 share off
    // their own position at effectively zero cost. In the real-world C0345
    // findings this is `repay(1)` or `withdraw(1 share)`.
    function burnOneShare() external {
        Position storage p = positions[msg.sender];
        if (p.shares > 0) {
            p.shares -= 1;
        }
    }

    // VULN: liquidate() gates on `shares > 0`. A borrower observing a
    // pending liquidation can frontrun with `burnOneShare()` — their
    // shares drop to 0 (or mismatch expected) and this require reverts.
    // The liquidator's gas is burned; the borrower's underwater position
    // lives another block.
    function liquidate(address borrower, uint256 amount) external {
        Position storage p = positions[borrower];
        require(p.shares > 0, "no shares to seize");
        p.debt -= amount;
        p.shares = 0;
    }
}
