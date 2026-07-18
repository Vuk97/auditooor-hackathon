// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - perpetual-position-stuck-umbrella
// VULN: liquidation iterates over unbounded per-account options/positions array.
// Attacker can open thousands of positions to make liquidation exceed block gas limit.

contract VulnPerpetualPositionStuck {
    struct Option {
        uint256 strikePrice;
        uint256 amount;
        uint256 expiry;
        bool settled;
    }

    struct Account {
        uint256 collateral;
        uint256 debt;
        Option[] options; // VULN: unbounded array
    }

    mapping(address => Account) public accounts;
    uint256 public constant MIN_POSITION = 1e6;

    function openOption(uint256 strikePrice, uint256 amount, uint256 expiry) external payable {
        // No cap on number of options per account - can be called indefinitely
        accounts[msg.sender].options.push(Option(strikePrice, amount, expiry, false));
        accounts[msg.sender].collateral += msg.value;
        accounts[msg.sender].debt += amount;
    }

    // VULN: liquidation iterates over ALL options with no gas guard.
    // Attacker with 10,000+ options makes this revert at block gas limit.
    function liquidate(address account) external {
        Account storage acc = accounts[account];
        require(acc.debt > acc.collateral * 150 / 100, "not liquidatable");

        // Iterates over unbounded options array - reverts if too many positions
        for (uint256 i = 0; i < acc.options.length; i++) {
            if (!acc.options[i].settled) {
                acc.options[i].settled = true;
                // settle option logic...
            }
        }
        // Account remains unliquidatable if gas runs out mid-loop
    }
}

contract VulnExitAfterLiquidationStuck {
    struct Position {
        uint256 collateral;
        uint256 debt;
        uint256 margin;
    }

    mapping(address => Position) public positions;

    function liquidatePosition(address account, uint256 repaidDebt, uint256 seizedCollateral) external {
        Position storage position = positions[account];
        position.debt -= repaidDebt;
        position.collateral -= seizedCollateral;
    }

    // VULN: exit subtracts debt again after liquidation already applied it.
    // A partially liquidated account can underflow or revert forever here.
    function exitVault() external returns (uint256 payout) {
        Position storage position = positions[msg.sender];
        payout = position.collateral - position.debt;
        position.margin -= position.debt;
        position.collateral = 0;
        position.debt = 0;
    }
}

contract VulnDustThresholdCloseStuck {
    struct Position {
        uint256 collateral;
        uint256 debt;
    }

    uint256 public minDebt = 100e18;
    mapping(address => Position) public positions;

    // VULN: partial close can leave remaining debt below minDebt. The same
    // threshold then blocks every later close/liquidation attempt.
    function closePosition(uint256 repayAmount) external {
        Position storage position = positions[msg.sender];
        require(repayAmount <= position.debt, "too much");
        uint256 remainingDebt = position.debt - repayAmount;
        bool closeAllowed = remainingDebt == 0 || remainingDebt >= minDebt;
        require(closeAllowed, "close leaves dust");
        position.debt = remainingDebt;
    }
}
