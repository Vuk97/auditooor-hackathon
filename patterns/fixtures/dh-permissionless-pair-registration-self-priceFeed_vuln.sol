// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PerpFactoryVuln {
    struct PairParams {
        address priceFeed;
        address poolOwner;
        address uniswapPool;
    }

    struct Pair {
        address priceFeed;
        address poolOwner;
    }

    mapping(uint256 => Pair) public pairs;
    uint256 public nextId;

    // Vuln: permissionless; any caller seeds priceFeed + poolOwner with
    // their own address. Subsequent trades use the attacker's oracle.
    function registerPair(PairParams calldata p) external returns (uint256 id) {
        id = ++nextId;
        pairs[id] = Pair({priceFeed: p.priceFeed, poolOwner: p.poolOwner});
    }
}
