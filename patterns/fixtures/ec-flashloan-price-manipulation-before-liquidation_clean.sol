// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILendingWithTWAP {
    // Lending protocol enforces TWAP price — not manipulable in single block
    function liquidateWithTWAPGuard(address borrower) external;
}

// CLEAN: lending protocol uses TWAP, making same-block price manipulation ineffective
// The flashloan callback CAN still call liquidate — but the price feed in the
// lending protocol uses a 30-min TWAP that the flashloan cannot move.
contract SafeLiquidatorClean {
    ILendingWithTWAP public lending;
    address public victimBorrower;

    constructor(address _lending, address _victim) {
        lending = ILendingWithTWAP(_lending);
        victimBorrower = _victim;
    }

    // CLEAN: even if called inside a flashloan, the lending protocol
    // uses TWAP-based prices that cannot be moved within one transaction
    function uniswapV2Call(address, uint256, uint256, bytes calldata) external {
        // The swap above (if any) does NOT affect the TWAP price feed
        // TWAP requires sustained price movement over 1800 seconds
        lending.liquidateWithTWAPGuard(victimBorrower); // TWAP-protected
        // Repay logic omitted for brevity
    }
}
