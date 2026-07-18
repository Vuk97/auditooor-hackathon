// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WithConstructorAndFallback {
    address public owner;
    uint256 public balance;

    constructor(address _owner) {
        owner = _owner;
    }

    receive() external payable {
        balance += msg.value;
    }

    fallback() external {
        revert("unknown function");
    }

    function withdraw(uint256 amount) external returns (bool) {
        return true;
    }
}
