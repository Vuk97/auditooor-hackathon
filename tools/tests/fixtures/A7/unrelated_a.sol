// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashBorrower {
    function onFlashLoan(bytes calldata data) external;
}

// WINDOW module in its OWN file, with NO reference to the sibling contract in
// unrelated_b.sol and no shared base. The two contracts merely happen to reuse
// the field name `totalReserves`. The relation predicate must keep this SILENT.
contract LonePool {
    uint256 public totalReserves;

    function flashLoan(address borrower, uint256 amount) external {
        totalReserves -= amount;
        IFlashBorrower(borrower).onFlashLoan("");
        totalReserves += amount;
    }
}
