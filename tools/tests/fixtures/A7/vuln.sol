// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashBorrower {
    function onFlashLoan(bytes calldata data) external;
}

// WINDOW MODULE: opens an external callback while its coupled state var
// `totalReserves` is in flight (decremented before the callback, restored
// after). CEI is arguably fine INSIDE this contract - the violation is
// cross-module.
contract Pool {
    uint256 public totalReserves;

    function flashLoan(address borrower, uint256 amount) external {
        totalReserves -= amount;                 // coupled state in flight
        IFlashBorrower(borrower).onFlashLoan(""); // <-- callback window
        totalReserves += amount;
    }
}

// SIBLING (read): a DIFFERENT contract, related by a type reference to Pool,
// reads the coupled `totalReserves` mid-window with no reentrancy guard.
contract PriceOracle {
    Pool public pool;

    function price() external view returns (uint256) {
        return pool.totalReserves() * 2;         // stale cross-contract read
    }
}

// SIBLING (write): a related contract (references Pool) with its own coupled
// `totalReserves` mirror it mutates unguarded during the window.
contract MirrorRegistry {
    uint256 public totalReserves;
    Pool public pool;

    function sync(uint256 v) external {
        totalReserves = v;                       // unguarded coupled write
    }
}
