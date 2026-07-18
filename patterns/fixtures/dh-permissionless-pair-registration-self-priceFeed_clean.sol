// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PerpFactoryClean {
    struct PairParams {
        address priceFeed;
        address poolOwner;
        address uniswapPool;
    }

    struct Pair {
        address priceFeed;
        address poolOwner;
    }

    address public owner;
    mapping(address => bool) public approvedOracle;
    mapping(uint256 => Pair) public pairs;
    uint256 public nextId;

    modifier onlyOwner() { require(msg.sender == owner, "OWNER"); _; }

    constructor() { owner = msg.sender; }

    // Clean: registration gated by onlyOwner; oracle must be whitelisted.
    function registerPair(PairParams calldata p) external onlyOwner returns (uint256 id) {
        require(approvedOracle[p.priceFeed], "ORACLE_NOT_APPROVED");
        id = ++nextId;
        pairs[id] = Pair({priceFeed: p.priceFeed, poolOwner: p.poolOwner});
    }
}
