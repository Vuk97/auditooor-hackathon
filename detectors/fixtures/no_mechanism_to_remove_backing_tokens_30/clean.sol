// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoMechanismToRemoveBackingTokens30Clean {
    struct BackingTokenDetails {
        bool isBackingToken;
        address oracle;
    }

    address[] public backingTokens;
    mapping(address => BackingTokenDetails) public backingTokenDetailsForAddress;

    function addBackingToken(address token, address oracle) external {
        require(!backingTokenDetailsForAddress[token].isBackingToken, "already backing");
        backingTokens.push(token);
        backingTokenDetailsForAddress[token].isBackingToken = true;
        backingTokenDetailsForAddress[token].oracle = oracle;
    }

    function updateBackingTokenOracle(address token, address oracle) external {
        require(backingTokenDetailsForAddress[token].isBackingToken, "unknown token");
        backingTokenDetailsForAddress[token].oracle = oracle;
    }

    function removeBackingToken(address token) external {
        require(backingTokenDetailsForAddress[token].isBackingToken, "unknown token");
        backingTokenDetailsForAddress[token].isBackingToken = false;
    }
}
