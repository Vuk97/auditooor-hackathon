// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PoolAddressMisleadingArgumentPositive {
    struct PoolKey {
        address poolDeployer;
        address token0;
        address token1;
    }

    function getPoolKey(
        address poolDeployer,
        address tokenA,
        address tokenB
    ) internal pure returns (PoolKey memory) {
        return PoolKey({poolDeployer: poolDeployer, token0: tokenA, token1: tokenB});
    }
}

contract MisleadingArgumentNamePositive {
    address internal immutable poolDeployer;

    constructor(address poolDeployer_) {
        poolDeployer = poolDeployer_;
    }

    function exposeVerifyCallback(
        address factory,
        address tokenA,
        address tokenB
    ) external view returns (address) {
        return verifyCallback(factory, tokenA, tokenB);
    }

    function verifyCallback(
        address factory,
        address tokenA,
        address tokenB
    ) internal view returns (address pool) {
        PoolAddressMisleadingArgumentPositive.PoolKey memory key =
            PoolAddressMisleadingArgumentPositive.getPoolKey(poolDeployer, tokenA, tokenB);
        factory;
        return key.poolDeployer;
    }
}
