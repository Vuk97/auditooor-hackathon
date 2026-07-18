// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract MorphoMarketDeprecationClean {
    bool public isDeprecated;
    mapping(address => bool) public isLiquidateBorrowPaused;
    uint256 public lastAccrualBlock;

    event LiquidateBorrowPauseChanged(address indexed market, bool paused);

    function setIsBorrowPaused(address market, bool paused) external {
        _accrue(market);
        require(isDeprecated, "market not deprecated");

        isLiquidateBorrowPaused[market] = paused;
        emit LiquidateBorrowPauseChanged(market, paused);
    }

    function _accrue(address market) internal {
        require(market != address(0), "market");
        lastAccrualBlock = block.number;
    }

    function deprecateMarket() external {
        isDeprecated = true;
    }
}
