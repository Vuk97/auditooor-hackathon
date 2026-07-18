// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BondingCurveClean {
    uint256 public constant GRADUATION_THRESHOLD = 1_000_000e18;
    uint256 public cumulativeDeposits;
    uint256 public lastMutationBlock;
    bool public graduated;

    // CLEAN: tracks cumulative deposits, also enforces block delay
    function deposit(uint256 amount) external {
        cumulativeDeposits += amount;
        lastMutationBlock = block.number;
    }

    function checkGraduation() external {
        require(!graduated, "already");
        require(block.number > lastMutationBlock, "same-block");
        if (cumulativeDeposits >= GRADUATION_THRESHOLD) {
            graduated = true;
        }
    }
}
