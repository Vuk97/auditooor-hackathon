// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: borrow reads totalBorrows without calling accrueInterest first
// Loss ref: Hundred Finance ~$7.4M, April 2023; InverseFinance ~$15M, April 2022
// https://rekt.news/hundred-rekt2/
contract CTokenVuln {
    uint256 public totalBorrows;
    uint256 public totalCash;
    uint256 public totalSupply;
    mapping(address => uint256) public borrowBalances;
    mapping(address => uint256) public accountTokens;
    uint256 public accrualBlockNumber;

    // VULN: borrow does NOT call accrueInterest() — uses stale totalBorrows
    function borrow(uint256 borrowAmount) external {
        // MISSING: accrueInterest() call here
        // totalBorrows is stale — under-reports real debt
        uint256 available = totalCash - totalBorrows; // stale, too large
        require(borrowAmount <= available, "insufficient liquidity");

        totalBorrows += borrowAmount;
        totalCash -= borrowAmount;
        borrowBalances[msg.sender] += borrowAmount;
        // borrow allowed against under-reported debt
    }
}
