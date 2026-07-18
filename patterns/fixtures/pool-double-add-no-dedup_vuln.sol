// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: classic MasterChef-style pool registry with no duplicate-add check.
// The same pool address can be pushed twice, double-counting reward shares
// in downstream iteration.
contract PoolDoubleAddVuln {
    struct PoolInfo {
        address lpToken;
        uint256 allocPoint;
    }

    PoolInfo[] public pools;
    address[] public poolList;
    mapping(uint256 => uint256) public poolInfo;
    uint256 public registeredPools;

    // VULN shape 1: addPool pushes to the pools array, no dedup check.
    function addPool(address lpToken, uint256 allocPoint) external {
        pools.push(PoolInfo(lpToken, allocPoint));
    }

    // VULN shape 2: registerPool with index-by-length but no prior-existence
    // check. Duplicate addresses silently occupy new indices.
    function registerPool(address lpToken) external {
        poolInfo[pools.length] = uint256(uint160(lpToken));
        pools.push(PoolInfo(lpToken, 1));
    }

    // VULN shape 3: addCurated uses push without any guard.
    function addCurated(address vault) external {
        poolList.push(vault);
        registeredPools += 1;
    }

    // VULN shape 4: createPool assigns by index and appends.
    function createPool(address lpToken) external {
        pools.push(PoolInfo(lpToken, 100));
    }
}
