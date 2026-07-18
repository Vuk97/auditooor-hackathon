// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: accrueInterest() called before any borrow operation
contract CTokenClean {
    uint256 public totalBorrows;
    uint256 public totalCash;
    uint256 public totalSupply;
    mapping(address => uint256) public borrowBalances;
    uint256 public accrualBlockNumber;
    uint256 public constant BORROW_RATE = 2e14; // simplified rate

    // Accrues interest to current block
    function accrueInterest() public {
        if (block.number == accrualBlockNumber) return;
        uint256 blockDelta = block.number - accrualBlockNumber;
        uint256 interestFactor = BORROW_RATE * blockDelta;
        uint256 interestAccumulated = totalBorrows * interestFactor / 1e18;
        totalBorrows += interestAccumulated;
        accrualBlockNumber = block.number;
    }

    // CLEAN: accrueInterest() called first — totalBorrows is current
    function borrow(uint256 borrowAmount) external {
        accrueInterest(); // update state to current block
        uint256 available = totalCash - totalBorrows;
        require(borrowAmount <= available, "insufficient liquidity");
        totalBorrows += borrowAmount;
        totalCash -= borrowAmount;
        borrowBalances[msg.sender] += borrowAmount;
    }
}
