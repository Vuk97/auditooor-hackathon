// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IUniswapV2Factory {
    function createPair(address, address) external returns (address);
    function getPair(address, address) external view returns (address);
}

contract LaunchClean {
    IUniswapV2Factory public factory;
    address public token;
    address public weth;

    function launch() external returns (address pair) {
        pair = factory.getPair(token, weth);
        if (pair == address(0)) {
            pair = factory.createPair(token, weth);
        }
    }
}
