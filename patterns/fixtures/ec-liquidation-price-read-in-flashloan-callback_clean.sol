// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILending {
    function liquidateWithPrice(address borrower, uint256 amount, uint256 snapshotPrice) external;
}

// CLEAN: price captured at liquidation entry point (before flashloan callback),
// passed as parameter — cannot be manipulated by flashloan within same tx
contract LiquidatorClean {
    ILending public lending;

    constructor(address _lending) { lending = ILending(_lending); }

    // CLEAN: callback only receives pre-captured price, does not re-read oracle
    function uniswapV2Call(address, uint256, uint256, bytes calldata data) external {
        (address borrower, uint256 snapshotPrice) = abi.decode(data, (address, uint256));
        // snapshotPrice was captured before flashloan was initiated
        // Lending contract validates snapshotPrice is within acceptable range
        lending.liquidateWithPrice(borrower, 100e18, snapshotPrice);
    }
}
