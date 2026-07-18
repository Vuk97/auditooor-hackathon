// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PerpVaultVuln {
    struct Position {
        uint256 size;
        uint256 entryPrice;
    }
    mapping(address => Position) public position;

    function openLong(uint256 size, uint256 entryPrice) external {
        position[msg.sender] = Position(size, entryPrice);
    }

    // BUG: values position at stored entryPrice, not live oracle.
    function withdraw() external returns (uint256 payout) {
        Position memory p = position[msg.sender];
        payout = (p.size * p.entryPrice) / 1e18;
        delete position[msg.sender];
    }
}
