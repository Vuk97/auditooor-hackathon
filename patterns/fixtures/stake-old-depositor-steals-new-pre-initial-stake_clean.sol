// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakeClean {
    uint256 public constant MINIMUM_LIQUIDITY = 10 ** 3;
    uint256 public totalSupply;
    uint256 public totalStaked;
    mapping(address => uint256) public shares;

    // CLEAN: first deposit burns MINIMUM_LIQUIDITY dead shares.
    function stake(uint256 amount) external {
        uint256 newShares;
        if (totalSupply == 0) {
            require(amount > MINIMUM_LIQUIDITY, "seed too small");
            newShares = amount - MINIMUM_LIQUIDITY;
            shares[address(1)] = MINIMUM_LIQUIDITY; // dead-share sink
            totalSupply = MINIMUM_LIQUIDITY;
        } else {
            newShares = amount * totalSupply / totalStaked;
        }
        shares[msg.sender] += newShares;
        totalSupply += newShares;
        totalStaked += amount;
    }
}
