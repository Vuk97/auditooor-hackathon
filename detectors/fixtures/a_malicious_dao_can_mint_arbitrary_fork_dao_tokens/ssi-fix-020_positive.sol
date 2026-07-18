// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousDaoForkMintPositive {
    error ForkWindowClosed();

    uint256 internal forkEndTimestamp;
    uint256 internal mintedForkDaoTokens;

    constructor() {
        forkEndTimestamp = block.timestamp + 7 days;
    }

    function executeFork() external returns (bool) {
        if (forkEndTimestamp <= block.timestamp) {
            revert ForkWindowClosed();
        }

        mintedForkDaoTokens += 1;
        return mintedForkDaoTokens > 0;
    }
}
