// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every add*Pool entrypoint rejects duplicates before pushing.
contract PoolDoubleAddClean {
    struct PoolInfo {
        address lpToken;
        uint256 allocPoint;
    }

    PoolInfo[] public pools;
    address[] public poolList;
    mapping(address => bool) public isPool;
    mapping(address => bool) public isRegistered;
    uint256 public registeredPools;

    // CLEAN: explicit !isPool dedup gate before push.
    function addPool(address lpToken, uint256 allocPoint) external {
        require(!isPool[lpToken], "pool exists");
        isPool[lpToken] = true;
        pools.push(PoolInfo(lpToken, allocPoint));
    }

    // CLEAN: require !registered before push.
    function registerPool(address lpToken) external {
        require(!isRegistered[lpToken], "already");
        isRegistered[lpToken] = true;
        pools.push(PoolInfo(lpToken, 1));
    }

    // CLEAN: zero-address AND duplicate checked.
    function addCurated(address vault) external {
        require(vault != address(0), "zero");
        require(!isPool[vault], "dup");
        isPool[vault] = true;
        poolList.push(vault);
        registeredPools += 1;
    }

    // CLEAN: uses alreadyAdded sentinel explicitly.
    function createPool(address lpToken) external {
        require(!isPool[lpToken], "alreadyAdded");
        isPool[lpToken] = true;
        pools.push(PoolInfo(lpToken, 100));
    }
}
