// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InitRaceAdminTakeoverClean {
    address public owner;
    address public immutable deployer;
    bool public initialized;

    constructor() {
        deployer = msg.sender;
    }

    function initialize(address newOwner) external {
        require(msg.sender == deployer, "only deployer");
        require(!initialized, "already initialized");
        owner = newOwner;
        initialized = true;
    }
}
