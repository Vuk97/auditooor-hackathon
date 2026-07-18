// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PoolAddressMisleadingArgumentClean {
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

contract MisleadingArgumentNameClean {
    function exposeVerifyCallback(
        address poolDeployer_,
        address tokenA,
        address tokenB
    ) external pure returns (address) {
        return verifyCallback(poolDeployer_, tokenA, tokenB);
    }

    function verifyCallback(
        address poolDeployer_,
        address tokenA,
        address tokenB
    ) internal pure returns (address pool) {
        PoolAddressMisleadingArgumentClean.PoolKey memory key =
            PoolAddressMisleadingArgumentClean.getPoolKey(poolDeployer_, tokenA, tokenB);
        return key.poolDeployer;
    }
}
