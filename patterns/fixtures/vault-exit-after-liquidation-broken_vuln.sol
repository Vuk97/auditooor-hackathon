// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: leveraged vault whose exit/redeem paths subtract debt (or loss /
// margin / collateral) from the user's position even after a prior
// liquidation already reduced both sides. No liquidation-flag guard.
contract VaultExitAfterLiquidationVuln {
    struct Position {
        uint256 collateral;
        uint256 debt;
        uint256 margin;
        uint256 loss;
    }

    mapping(address => Position) public position;
    mapping(address => uint256) public leverage;
    uint256 public vault;

    // Liquidation: reduces BOTH sides of the position in one step.
    function liquidate(address user, uint256 amount) external {
        Position storage p = position[user];
        p.collateral -= amount;
        p.debt -= amount;
    }

    // VULN 1: exit subtracts debt from collateral with no post-liquidation
    // guard. If liquidate() already ran, this double-subtracts.
    function exit() external {
        Position storage p = position[msg.sender];
        p.collateral -= p.debt;
        // transfer remaining collateral ...
    }

    // VULN 2: redeem path re-subtracts loss on the payout.
    function redeem(uint256 shares) external {
        Position storage p = position[msg.sender];
        p.loss -= shares;
    }

    // VULN 3: withdrawMax uses `collateral - debt` arithmetic form.
    function withdrawMax() external returns (uint256) {
        Position storage p = position[msg.sender];
        uint256 out = p.collateral - p.debt;
        return out;
    }

    // VULN 4: closePosition decrements margin on exit.
    function closePosition() external {
        Position storage p = position[msg.sender];
        p.margin -= 1;
    }
}
