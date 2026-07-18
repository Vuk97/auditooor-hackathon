// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: Same price / conversion math, but every division by a
// supply-family state read is preceded by a require(...>0) or a
// short-circuit `if (... == 0) return ...`. The negative guard regex
// suppresses the match.

interface IToken {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

library SafeMathLike {
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

contract PriceDivByZeroClean {
    using SafeMathLike for uint256;

    IToken public immutable underlying;
    uint256 public totalSupply;
    uint256 public reserves;
    uint256 public supply;

    constructor(address _u) {
        underlying = IToken(_u);
    }

    // CLEAN shape 1: short-circuit on empty supply → ERC4626 1:1 fallback.
    function convertToAssets(uint256 shares) external view returns (uint256) {
        if (totalSupply == 0) {
            return shares; // 1:1 on fresh vault
        }
        uint256 assets = underlying.balanceOf(address(this));
        return shares * assets / totalSupply;
    }

    // CLEAN shape 2: explicit require before library div on reserves.
    function spotPrice(uint256 amountIn) external view returns (uint256) {
        require(reserves > 0, "empty pool");
        uint256 n = amountIn * 1e18;
        return n.div(reserves);
    }

    // CLEAN shape 3: require(supply != 0) before division by supply.
    function exchangeRate(uint256 underlyingAmount) external view returns (uint256) {
        require(supply != 0, "no supply");
        return underlyingAmount * 1e18 / supply;
    }
}
