// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurveGameToken {
    function mint(address to, uint256 amount) external;
}

contract Fire14LinearCurveUncheckedPositive {
    ICurveGameToken public immutable token;
    uint256 public unitPrice = 3e15;
    uint256 public scale = 1e18;
    uint256 public curveMultiplier = 2e18;
    uint256 public emissionMultiplier = 5e17;
    uint256 public reserveBase;

    constructor(ICurveGameToken curveToken) {
        token = curveToken;
    }

    function buy(uint256 requestedTokens) external payable returns (uint256 cost) {
        unchecked {
            cost = requestedTokens * unitPrice / scale;
        }
        require(msg.value >= cost, "underpaid");

        uint256 minted;
        unchecked {
            minted = curveMultiplier * requestedTokens;
        }

        reserveBase += cost;
        token.mint(msg.sender, minted);
    }

    function enter(uint256 quantity) external {
        uint256 sharesToMint;
        unchecked {
            sharesToMint = quantity * emissionMultiplier;
        }
        reserveBase += quantity;
        token.mint(msg.sender, sharesToMint);
    }
}
