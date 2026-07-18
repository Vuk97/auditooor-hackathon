// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2FactoryLike {
    function createPair(address tokenA, address tokenB) external returns (address pair);
}

contract PairLaunchFlowVulnerable {
    IUniswapV2FactoryLike internal immutable factory;
    address internal createpairTokenA;
    address internal createpairTokenB;
    bool internal createpairRequested;

    constructor(IUniswapV2FactoryLike factory_, address tokenA_, address tokenB_) {
        factory = factory_;
        createpairTokenA = tokenA_;
        createpairTokenB = tokenB_;
    }

    function createPairForListing() external returns (address pair) {
        require(!createpairRequested, "pair already requested");
        createpairRequested = true;

        address tokenA = createpairTokenA;
        address tokenB = createpairTokenB;
        pair = factory.createPair(tokenA, tokenB);
    }
}
