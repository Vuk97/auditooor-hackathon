// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20Bal { function balanceOf(address a) external view returns (uint256); }

contract MarketVuln {
    IERC20Bal public underlying;
    uint256 public totalSupply = 1;
    uint256 public totalBorrows;
    uint256 public reserves;

    function exchangeRate() public view returns (uint256) {
        uint256 cash = underlying.balanceOf(address(this));
        return (cash + totalBorrows - reserves) * 1e18 / totalSupply;
    }
}
