// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Grantor {
    address public owner;
    mapping(address => bool) public operators;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function addOperator(address op) external onlyOwner {
        operators[op] = true;
    }

    function removeOperator(address op) external onlyOwner {
        operators[op] = false;
    }
}
