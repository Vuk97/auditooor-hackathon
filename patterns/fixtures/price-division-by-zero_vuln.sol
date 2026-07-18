// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: Price / conversion math divides by a supply-family state read
// without a prior non-zero guard. When totalSupply / reserve is zero
// (empty vault, fresh pool), every call reverts with DIV-by-zero, and
// the pricing feature is DoS'd.

interface IToken {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

library SafeMathLike {
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

contract PriceDivByZeroVuln {
    using SafeMathLike for uint256;

    IToken public immutable underlying;
    uint256 public totalSupply;     // vault shares outstanding
    uint256 public reserves;        // pool reserve balance
    uint256 public supply;          // alternate name

    constructor(address _u) {
        underlying = IToken(_u);
    }

    // VULN shape 1: native / division by totalSupply, no `require(totalSupply > 0)`.
    function convertToAssets(uint256 shares) external view returns (uint256) {
        uint256 assets = underlying.balanceOf(address(this));
        return shares * assets / totalSupply;
    }

    // VULN shape 2: SafeMath-style `.div(reserve*)` with no guard.
    function spotPrice(uint256 amountIn) external view returns (uint256) {
        uint256 n = amountIn * 1e18;
        return n.div(reserves);
    }

    // VULN shape 3: division by `supply` directly — caught by the
    // `\/\s*supply` branch of the positive regex.
    function exchangeRate(uint256 underlyingAmount) external view returns (uint256) {
        return underlyingAmount * 1e18 / supply;
    }
}
