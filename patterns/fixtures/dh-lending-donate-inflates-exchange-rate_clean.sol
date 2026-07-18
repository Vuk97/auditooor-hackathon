// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract MarketClean {
    uint256 public _cash;
    uint256 public totalSupply = 1;
    uint256 public totalBorrows;
    uint256 public reserves;

    function exchangeRate() public view returns (uint256) {
        return (_cash + totalBorrows - reserves) * 1e18 / totalSupply;
    }
}
