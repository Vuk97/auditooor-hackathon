// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ParameterizedPoolPositive {
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
        initialized = true;
        feeBps = initialFee;
        A = initialA;
        gamma = initialGamma;
        tokenDecimals = decimals_;
    }

    function quoteFactoryPath() external view returns (address) {
        return factory;
    }
}
