// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ADarkAgeCanEndPrematurelyClean {
    uint256 public supply;
    uint256 public maxSupply = 10000;

    function updateSupply(uint256 newSupply) external {
        require(newSupply <= maxSupply, "supply cap");
        supply = newSupply;
    }
}
