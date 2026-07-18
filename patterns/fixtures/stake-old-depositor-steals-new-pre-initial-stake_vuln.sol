// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakeVuln {
    uint256 public totalSupply;
    uint256 public totalStaked;
    mapping(address => uint256) public shares;

    // VULN: no first-depositor seed / minimum-liquidity mint.
    function stake(uint256 amount) external {
        uint256 newShares;
        if (totalSupply == 0) {
            newShares = amount;
        } else {
            newShares = amount * totalSupply / totalStaked;
        }
        shares[msg.sender] += newShares;
        totalSupply += newShares;
        totalStaked += amount;
    }
}
