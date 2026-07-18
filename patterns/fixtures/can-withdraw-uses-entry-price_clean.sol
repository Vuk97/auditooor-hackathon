// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle { function getPrice() external view returns (uint256); }

contract PerpVaultClean {
    struct Position { uint256 size; uint256 entryPrice; }
    mapping(address => Position) public position;
    IOracle public oracle;

    function openLong(uint256 size, uint256 entryPrice) external {
        position[msg.sender] = Position(size, entryPrice);
    }

    // Clean: value at live oracle price; entryPrice only used for PnL math.
    function withdraw() external returns (uint256 payout) {
        Position memory p = position[msg.sender];
        uint256 currentPrice = oracle.getPrice();
        payout = (p.size * currentPrice) / 1e18;
        delete position[msg.sender];
    }
}
