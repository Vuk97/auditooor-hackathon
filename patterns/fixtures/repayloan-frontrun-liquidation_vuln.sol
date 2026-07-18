// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RepayFrontrunVuln {
    struct Position {
        uint256 debt;
        uint256 collateral;
        bool liquidated;
    }

    mapping(address => Position) public positions;

    // Permissionless liquidation — satisfies contract-level precondition.
    // Because it's permissionless, any searcher can call it in front of a
    // pending repay tx.
    function liquidate(address borrower) external {
        Position storage p = positions[borrower];
        // pretend-compute that position is unhealthy …
        p.liquidated = true;
        p.collateral = 0;
    }

    // VULN: repayLoan requires position be non-liquidated. An attacker who
    // sees the pending repay in the mempool can frontrun with liquidate()
    // and cause this require to revert.
    function repayLoan(uint256 amount) external {
        Position storage p = positions[msg.sender];
        require(!p.liquidated, "position liquidated");
        p.debt -= amount;
    }
}
