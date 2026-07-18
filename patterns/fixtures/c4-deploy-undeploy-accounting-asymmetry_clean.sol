// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

interface IMarket {
    function deposit(uint256 amount) external;
    function redeem(uint256 amount) external;
}

contract StrategyClean {
    uint256 public _deployedAmount;
    IERC20 public asset;
    IMarket public market;

    function deploy(uint256 amount) external {
        _deployedAmount += amount;
        asset.transfer(address(market), amount);
        market.deposit(amount);
    }

    function undeploy(uint256 amount) external {
        _deployedAmount -= amount;
        market.redeem(amount);
        asset.transfer(msg.sender, amount);
    }
}
