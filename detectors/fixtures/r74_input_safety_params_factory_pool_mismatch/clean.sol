// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ParameterizedPoolClean {
    uint256 internal constant MIN_FEE = 1;
    uint256 internal constant MAX_FEE = 10_000;
    uint256 internal constant MIN_A = 10;
    uint256 internal constant MAX_A = 1_000_000;
    uint256 internal constant MIN_GAMMA = 1e18;
    uint256 internal constant MAX_GAMMA = 1e24;

    address public factory;
    uint256 public feeBps;
    uint256 public A;
    uint256 public gamma;
    uint8[2] public tokenDecimals;
    bool public initialized;

    constructor(address factory_) {
        factory = factory_;
    }

    function initialize(
        uint256 initialFee,
        uint256 initialA,
        uint256 initialGamma,
        uint8[2] calldata decimals_
    ) external {
        require(!initialized, "already initialized");
        require(initialFee >= MIN_FEE && initialFee <= MAX_FEE, "fee");
        require(initialA >= MIN_A && initialA <= MAX_A, "A");
        require(initialGamma >= MIN_GAMMA && initialGamma <= MAX_GAMMA, "gamma");
        initialized = true;
        feeBps = initialFee;
        A = initialA;
        gamma = initialGamma;
        tokenDecimals = decimals_;
    }
}
