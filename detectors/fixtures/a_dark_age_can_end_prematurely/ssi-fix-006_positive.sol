// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ADarkAgeCanEndPrematurelyPositive {
    uint256 public supply;

    function updateSupply(uint256 newSupply) external {
        supply = newSupply;
    }
}
