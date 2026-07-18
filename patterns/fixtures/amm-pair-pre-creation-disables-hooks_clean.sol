// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFactory {
    function createPair(address, address) external returns (address);
    function getPair(address, address) external view returns (address);
}

contract LaunchpadClean {
    IFactory public factory;
    mapping(address => address) public hookFor;

    function launch(address tokenA, address tokenB, address hook) external {
        address existing = factory.getPair(tokenA, tokenB);
        address pair = existing != address(0) ? existing : factory.createPair(tokenA, tokenB);
        hookFor[pair] = hook;
    }

    function migrateHook(address pair, address hook) external {
        // permissioned in real impl
        hookFor[pair] = hook;
    }
}
