// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RebaseBorrowPoolPositive {
    address public aToken;
    uint256 public pseudoTotalBorrow;
    uint256 public lastAccrual;

    constructor(address token) {
        aToken = token;
        lastAccrual = block.timestamp;
    }

    function _accrueInterest(uint256 borrowRate) external {
        uint256 dt = block.timestamp - lastAccrual;
        uint256 interestFactor = borrowRate * dt;
        pseudoTotalBorrow += (pseudoTotalBorrow * interestFactor) / 1e18;
        lastAccrual = block.timestamp;
    }
}
