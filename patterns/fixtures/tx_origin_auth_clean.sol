// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TxOriginClean {
    address public owner;

    constructor() { owner = msg.sender; }

    // CLEAN: msg.sender used for auth
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }
}
