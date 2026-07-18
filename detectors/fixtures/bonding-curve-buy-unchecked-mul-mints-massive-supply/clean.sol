// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurveGameToken {
    function mint(address to, uint256 amount) external;
}

library FullMath {
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        return a * b / denominator;
    }
}

contract Fire14LinearCurveCheckedClean {
    ICurveGameToken public immutable token;
    uint256 public constant MAX_BUY = 1e30;
    uint256 public unitPrice = 3e15;
    uint256 public scale = 1e18;
    uint256 public curveMultiplier = 2e18;
    uint256 public emissionMultiplier = 5e17;
    uint256 public reserveBase;

    constructor(ICurveGameToken curveToken) {
        token = curveToken;
    }

    function buy(uint256 requestedTokens) external payable returns (uint256 cost) {
        require(requestedTokens <= MAX_BUY, "exceeds curve cap");
        unchecked {
            cost = requestedTokens * unitPrice / scale;
        }
        require(msg.value >= cost, "underpaid");

        uint256 minted = FullMath.mulDiv(requestedTokens, curveMultiplier, 1e18);
        reserveBase += cost;
        token.mint(msg.sender, minted);
    }

    function enter(uint256 quantity) external {
        uint256 sharesToMint = FullMath.mulDiv(quantity, emissionMultiplier, 1e18);
        reserveBase += quantity;
        token.mint(msg.sender, sharesToMint);
    }
}
