// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract LiquidatorSelfRebateClean {
    struct Position {
        uint256 debt;
        uint256 collateral;
    }

    mapping(address => Position) public positions;
    IERC20Like public collateralToken;

    // CLEAN: explicit self-liquidation guard. The borrower cannot call
    // liquidate() against themselves, so they cannot self-rebate the
    // seized collateral AND the debt write-down. Detector does NOT fire:
    // the `require(msg.sender != borrower, …)` string satisfies the
    // negative-anchor `body_not_contains_regex` → the whole match
    // predicate fails.
    function liquidate(address borrower, uint256 repayAmount) external {
        require(msg.sender != borrower, "self-liquidation");
        Position storage p = positions[borrower];
        uint256 seize = p.collateral;
        p.collateral = 0;
        p.debt -= repayAmount;
        collateralToken.transfer(msg.sender, seize);
    }
}
