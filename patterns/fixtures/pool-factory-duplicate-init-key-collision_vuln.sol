// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: factory derives pool key from keccak(tokenA, tokenB[, fee]) without
// canonical ordering and without checking whether the key is already
// populated. Same logical pair maps to two different keys when reversed,
// and re-invocation silently overwrites pool state.
contract PoolFactoryVuln {
    mapping(bytes32 => address) public pools;
    mapping(bytes32 => address) public poolByKey;
    address public factory;
    address[] public allPools;

    // VULN 1: abi.encode with no ordering / existence check.
    function createPool(address tokenA, address tokenB, uint24 fee) external returns (address p) {
        bytes32 key = keccak256(abi.encode(tokenA, tokenB, fee));
        p = address(uint160(uint256(key)));
        pools[key] = p;
        allPools.push(p);
    }

    // VULN 2: abi.encodePacked — same category, also unordered.
    function deployPool(address tokenA, address tokenB) external returns (address p) {
        bytes32 key = keccak256(abi.encodePacked(tokenA, tokenB));
        p = address(uint160(uint256(key)));
        poolByKey[key] = p;
    }

    // VULN 3: getPoolId helper, still no ordering, still no dedup.
    function initializePool(address tokenA, address tokenB) external returns (bytes32 id) {
        id = getPoolId(tokenA, tokenB);
        pools[id] = msg.sender;
    }

    function getPoolId(address a, address b) internal pure returns (bytes32) {
        return keccak256(abi.encode(a, b));
    }

    // VULN 4: registerPool with hash-derived key, no guard.
    function registerPool(address tokenA, address tokenB, uint24 fee) external {
        bytes32 key = keccak256(abi.encode(tokenA, tokenB, fee));
        pools[key] = msg.sender;
    }
}
