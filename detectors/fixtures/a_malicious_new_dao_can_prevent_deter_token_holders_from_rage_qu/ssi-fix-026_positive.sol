// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NewDaoRageQuitAssetInclusionPositive {
    mapping(address => uint256) internal balanceOf;
    address[] internal erc20TokensToIncludeInQuit;
    uint256 internal processedExits;

    constructor() {
        balanceOf[msg.sender] = 3;
        erc20TokensToIncludeInQuit.push(address(0xBEEF));
        erc20TokensToIncludeInQuit.push(address(0xCAFE));
    }

    function transfer(address account, uint256 amount) external returns (bool) {
        processedExits += erc20TokensToIncludeInQuit.length;
        return balanceOf[account] + processedExits >= amount;
    }
}
