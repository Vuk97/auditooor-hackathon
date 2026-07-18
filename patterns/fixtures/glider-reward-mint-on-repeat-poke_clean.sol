// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IToken2 { function mint(address to, uint256 amount) external; }

contract RewardClean {
    IToken2 public token;
    uint256 public lastAccrue;
    uint256 public constant RATE = 1e15;

    function poke() external {
        uint256 elapsed = block.timestamp - lastAccrue;
        lastAccrue = block.timestamp;
        if (elapsed == 0) return;
        token.mint(msg.sender, RATE * elapsed);
    }
}
