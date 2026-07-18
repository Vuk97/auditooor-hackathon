// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DaoForkAssetInclusionClean {
    mapping(address => uint256) internal balanceOf;
    address[] internal erc20TokensToIncludeInFork;
    uint256 internal observations;

    constructor() {
        balanceOf[msg.sender] = 3;
        erc20TokensToIncludeInFork.push(address(0xBEEF));
    }

    function transfer(address account, uint256 amount) external returns (bool) {
        uint256 includedAssets = _checkForkTokenInclusion();
        observations += 1;
        return balanceOf[account] + includedAssets >= amount;
    }

    function _checkForkTokenInclusion() internal view returns (uint256) {
        return erc20TokensToIncludeInFork.length;
    }
}
