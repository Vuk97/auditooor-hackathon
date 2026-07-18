// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IATokenBalance {
    function balanceOf(address account) external view returns (uint256);
}

contract RebaseBorrowPoolClean {
    IATokenBalance public aToken;
    uint256 public pseudoTotalBorrow;
    uint256 public stored;
    uint256 public lastAccrual;

    constructor(IATokenBalance token) {
        aToken = token;
        lastAccrual = block.timestamp;
    }

    function _accrueInterest(uint256 borrowRate) external {
        uint256 dt = block.timestamp - lastAccrual;
        uint256 interestFactor = borrowRate * dt;
        uint256 currentBalance = IATokenBalance(address(aToken)).balanceOf(address(this));
        uint256 rebaseAccrued = currentBalance > stored ? currentBalance - stored : 0;
        pseudoTotalBorrow += ((pseudoTotalBorrow + rebaseAccrued) * interestFactor) / 1e18;
        stored = currentBalance;
        lastAccrual = block.timestamp;
    }
}
