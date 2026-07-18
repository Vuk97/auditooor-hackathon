// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every exit / redeem path consults a wasLiquidated /
// liquidationNonce guard before subtracting debt or collateral. The
// double-subtraction is short-circuited when the liquidation flow already
// reduced the position.
contract VaultExitAfterLiquidationClean {
    struct Position {
        uint256 collateral;
        uint256 debt;
        uint256 margin;
        uint256 loss;
        bool wasLiquidated;
        uint256 liquidationNonce;
    }

    mapping(address => Position) public position;
    mapping(address => uint256) public leverage;
    uint256 public vault;
    uint256 public liquidationCount;

    function liquidate(address user, uint256 amount) external {
        Position storage p = position[user];
        p.collateral -= amount;
        p.debt -= amount;
        p.wasLiquidated = true;
        p.liquidationNonce += 1;
        liquidationCount += 1;
    }

    // CLEAN 1: exit checks wasLiquidated before double-subtracting.
    function exit() external {
        Position storage p = position[msg.sender];
        if (p.wasLiquidated) {
            // already adjusted by liquidation — skip.
            p.wasLiquidated = false;
            return;
        }
        p.collateral -= p.debt;
    }

    // CLEAN 2: redeem guarded by liquidationNonce comparison.
    function redeem(uint256 shares) external {
        Position storage p = position[msg.sender];
        require(p.liquidationNonce == 0, "post-liq adjust required");
        p.loss -= shares;
    }

    // CLEAN 3: withdrawMax branches on liquidated flag before the arithmetic.
    function withdrawMax() external returns (uint256) {
        Position storage p = position[msg.sender];
        if (p.wasLiquidated) {
            return p.collateral;
        }
        uint256 out = p.collateral - p.debt;
        return out;
    }

    // CLEAN 4: closePosition uses postLiquidationAdjust helper.
    function closePosition() external {
        Position storage p = position[msg.sender];
        postLiquidationAdjust(p);
    }

    function postLiquidationAdjust(Position storage p) internal {
        if (!p.wasLiquidated) {
            p.margin -= 1;
        }
    }
}
