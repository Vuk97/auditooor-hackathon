// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrivilegedFunctionMissingOnlyownerClean {
    address public owner;
    address public treasury;

    constructor() {
        owner = msg.sender;
        treasury = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function rotateOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function setTreasury(address newTreasury) external onlyOwner {
        treasury = newTreasury;
    }
}
