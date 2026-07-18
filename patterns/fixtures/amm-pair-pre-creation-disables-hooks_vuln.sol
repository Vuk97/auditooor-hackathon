// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFactory { function createPair(address, address) external returns (address); }

contract LaunchpadVuln {
    IFactory public factory;
    mapping(address => address) public hookFor;

    // VULN: only registers hook at create-time; no migration path
    function launch(address tokenA, address tokenB, address hook) external {
        address pair = factory.createPair(tokenA, tokenB);
        hookFor[pair] = hook;
    }
}
