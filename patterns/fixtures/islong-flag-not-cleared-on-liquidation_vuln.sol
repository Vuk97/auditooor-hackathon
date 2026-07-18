// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IsLongFlagNotClearedOnLiquidationVuln {
    struct Position { uint256 amount; bool isLong; uint256 entryPrice; }
    mapping(address => Position) public positions;

    function open(address user, uint256 amount, bool isLong) external {
        // VULN: assumes positions[user].isLong is cleared; it is not.
        require(positions[user].amount == 0 || positions[user].isLong == isLong, "dir lock");
        positions[user] = Position(amount, isLong, 100);
    }

    function liquidate(address user) external {
        // VULN: only clears amount, leaves isLong stale.
        positions[user].amount = 0;
    }
}
