// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every factory entrypoint canonicalises the token pair AND
// rejects duplicate keys before writing.
contract PoolFactoryClean {
    mapping(bytes32 => address) public pools;
    mapping(bytes32 => address) public poolByKey;
    mapping(bytes32 => bool) public exists;
    address public factory;
    address[] public allPools;

    // CLEAN 1: require tokenA < tokenB, and require pools[key] == address(0).
    function createPool(address tokenA, address tokenB, uint24 fee) external returns (address p) {
        require(tokenA < tokenB, "unordered");
        bytes32 key = keccak256(abi.encode(tokenA, tokenB, fee));
        require(pools[key] == address(0), "exists");
        p = address(uint160(uint256(key)));
        pools[key] = p;
        allPools.push(p);
    }

    // CLEAN 2: require token0 < token1 form accepted by the DSL regex.
    function deployPool(address token0, address token1) external returns (address p) {
        require(token0 < token1, "unordered");
        bytes32 key = keccak256(abi.encodePacked(token0, token1));
        require(!exists[key], "dup");
        exists[key] = true;
        p = address(uint160(uint256(key)));
        poolByKey[key] = p;
    }

    // CLEAN 3: getPoolId with canonical order via sort(...).
    function initializePool(address tokenA, address tokenB) external returns (bytes32 id) {
        (address a, address b) = sort(tokenA, tokenB);
        id = getPoolId(a, b);
        require(pools[id] == address(0), "exists");
        pools[id] = msg.sender;
    }

    function sort(address a, address b) internal pure returns (address, address) {
        return a < b ? (a, b) : (b, a);
    }

    function getPoolId(address a, address b) internal pure returns (bytes32) {
        return keccak256(abi.encode(a, b));
    }

    // CLEAN 4: registerPool guards against duplicate key.
    function registerPool(address tokenA, address tokenB, uint24 fee) external {
        require(tokenA < tokenB, "unordered");
        bytes32 key = keccak256(abi.encode(tokenA, tokenB, fee));
        require(!exists[key], "exists");
        exists[key] = true;
        pools[key] = msg.sender;
    }
}
