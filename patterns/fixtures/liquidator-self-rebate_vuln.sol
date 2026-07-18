// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract LiquidatorSelfRebateVuln {
    struct Position {
        uint256 debt;
        uint256 collateral;
    }

    mapping(address => Position) public positions;
    IERC20Like public collateralToken;

    // VULN: liquidate() transfers seized collateral to msg.sender with no
    // `msg.sender != borrower` guard. A borrower whose own position is
    // unhealthy can call this against themselves, receiving the collateral
    // AND clearing their own debt. Detector fires: transfer(msg.sender…)
    // is present AND the self-liquidation guard regex is absent.
    function liquidate(address borrower, uint256 repayAmount) external {
        Position storage p = positions[borrower];
        // (pretend-compute: position unhealthy)
        uint256 seize = p.collateral;
        p.collateral = 0;
        p.debt -= repayAmount;
        collateralToken.transfer(msg.sender, seize);
    }
}
