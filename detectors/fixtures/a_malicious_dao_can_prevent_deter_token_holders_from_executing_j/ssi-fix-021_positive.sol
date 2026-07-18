// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DaoForkAssetInclusionPositive {
    mapping(address => uint256) internal balanceOf;
    address[] internal erc20TokensToIncludeInFork;
    uint256 internal observations;

    constructor() {
        balanceOf[msg.sender] = 3;
        erc20TokensToIncludeInFork.push(address(0xBEEF));
    }

    function transfer(address account, uint256 amount) external returns (bool) {
        observations += 1;
        return balanceOf[account] + erc20TokensToIncludeInFork.length >= amount;
    }
}
