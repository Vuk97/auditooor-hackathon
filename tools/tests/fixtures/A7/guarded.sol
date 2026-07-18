// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashBorrower {
    function onFlashLoan(bytes calldata data) external;
}

// Same coupled cross-module structure as vuln.sol, but the SIBLINGS carry a
// reentrancy guard -> the tool must stay SILENT. The mutation-verify removes
// `nonReentrant` from a sibling and the tool must then FIRE.
contract Pool {
    uint256 public totalReserves;

    function flashLoan(address borrower, uint256 amount) external {
        totalReserves -= amount;
        IFlashBorrower(borrower).onFlashLoan("");
        totalReserves += amount;
    }
}

contract PriceOracle {
    Pool public pool;

    function price() external view nonReentrant returns (uint256) {
        return pool.totalReserves() * 2;
    }
}

contract MirrorRegistry {
    uint256 public totalReserves;
    Pool public pool;

    function sync(uint256 v) external nonReentrant {
        totalReserves = v;
    }
}
