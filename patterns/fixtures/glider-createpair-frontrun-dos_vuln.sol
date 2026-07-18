// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IUniswapV2Factory {
    function createPair(address, address) external returns (address);
    function getPair(address, address) external view returns (address);
}

contract LaunchVuln {
    IUniswapV2Factory public factory;
    address public token;
    address public weth;

    function launch() external returns (address pair) {
        // VULN: no getPair precheck
        pair = factory.createPair(token, weth);
    }
}
