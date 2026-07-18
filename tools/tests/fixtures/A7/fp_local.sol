// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashBorrower {
    function onFlashLoan(bytes calldata data) external;
}

// FP-GUARD: the window fn's coupled-looking write `reserveDelta` is a LOCAL,
// not a state variable, so it is NOT a genuine cross-module storage coupling.
// The tool must stay SILENT even though a sibling references `reserveDelta`.
contract Pool {
    function flashLoan(address borrower, uint256 amount) external {
        uint256 reserveDelta = amount;                 // local, not storage
        IFlashBorrower(borrower).onFlashLoan("");
        reserveDelta = reserveDelta + 1;
    }
}

contract Watcher {
    Pool public pool;

    function look(uint256 reserveDelta) external view returns (uint256) {
        return reserveDelta;                           // coincidental name
    }
}
