// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract MorphoMarketDeprecationPositive {
    bool public isDeprecated;
    mapping(address => bool) public isLiquidateBorrowPaused;

    event LiquidateBorrowPauseChanged(address indexed market, bool paused);

    function setIsBorrowPaused(address market, bool paused) external {
        require(isDeprecated, "market not deprecated");

        isLiquidateBorrowPaused[market] = paused;
        emit LiquidateBorrowPauseChanged(market, paused);
    }

    function deprecateMarket() external {
        isDeprecated = true;
    }
}
