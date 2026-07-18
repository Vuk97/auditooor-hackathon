// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IToken { function mint(address to, uint256 amount) external; }

contract RewardVuln {
    IToken public token;
    uint256 public constant REWARD = 1e18;

    function poke() external {
        token.mint(msg.sender, REWARD);
    }
}
