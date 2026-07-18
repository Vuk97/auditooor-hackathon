// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OperatorRegistryClean {
    address public owner;
    mapping(address => bool) public operators;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function addOperator(address op) external onlyOwner {
        operators[op] = true;
    }

    function removeOperator(address op) external onlyOwner {
        operators[op] = false;
    }
}
