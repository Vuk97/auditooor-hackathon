// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - perpetual-position-stuck-umbrella
// CLEAN: cap on positions per account enforced at open; liquidation is O(1) per positionId.

contract CleanPerpetualPositions {
    struct Option {
        uint256 strikePrice;
        uint256 amount;
        uint256 expiry;
        bool settled;
    }

    uint256 public constant MAX_OPTIONS = 20; // CLEAN: explicit cap

    mapping(address => Option[]) public accountOptions;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function openOption(uint256 strikePrice, uint256 amount, uint256 expiry) external payable {
        // CLEAN: require option count below cap before pushing
        require(accountOptions[msg.sender].length < MAX_OPTIONS, "too many positions");
        accountOptions[msg.sender].push(Option(strikePrice, amount, expiry, false));
        collateral[msg.sender] += msg.value;
        debt[msg.sender] += amount;
    }

    // CLEAN: liquidate by individual positionId - O(1) gas per liquidation call.
    function liquidate(address account, uint256 positionId) external {
        require(debt[account] > collateral[account] * 150 / 100, "not liquidatable");
        require(positionId < accountOptions[account].length, "invalid id");
        require(!accountOptions[account][positionId].settled, "already settled");
        accountOptions[account][positionId].settled = true;
        // settle option logic...
    }
}

contract CleanExitAfterLiquidation {
    struct Position {
        uint256 collateral;
        uint256 debt;
        uint256 margin;
        bool wasLiquidated;
    }

    mapping(address => Position) public positions;

    function liquidatePosition(address account, uint256 repaidDebt, uint256 seizedCollateral) external {
        Position storage position = positions[account];
        position.debt -= repaidDebt;
        position.collateral -= seizedCollateral;
        position.wasLiquidated = true;
    }

    // CLEAN: post-liquidation state is explicit, so exit applies debt once.
    function exitVault() external returns (uint256 payout) {
        Position storage position = positions[msg.sender];
        if (position.wasLiquidated) {
            payout = position.collateral;
        } else {
            payout = position.collateral - position.debt;
        }
        position.margin = 0;
        position.collateral = 0;
        position.debt = 0;
        position.wasLiquidated = false;
    }
}

contract CleanDustThresholdClose {
    struct Position {
        uint256 collateral;
        uint256 debt;
    }

    uint256 public minDebt = 100e18;
    mapping(address => Position) public positions;

    // CLEAN: sub-minimum residual debt is folded into the final close.
    function closePosition(uint256 repayAmount) external {
        Position storage position = positions[msg.sender];
        require(repayAmount <= position.debt, "too much");
        uint256 remainingDebt = position.debt - repayAmount;
        if (remainingDebt > 0 && remainingDebt < minDebt) {
            repayAmount += remainingDebt;
            remainingDebt = 0;
        }
        require(repayAmount > 0, "zero close");
        position.debt = remainingDebt;
    }
}
