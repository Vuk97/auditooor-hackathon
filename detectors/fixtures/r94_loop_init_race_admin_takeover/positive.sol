// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InitRaceAdminTakeoverPositive {
    address public owner;
    bool public initialized;

    function initialize(address newOwner) external {
        require(!initialized, "already initialized");
        owner = newOwner;
        initialized = true;
    }
}
