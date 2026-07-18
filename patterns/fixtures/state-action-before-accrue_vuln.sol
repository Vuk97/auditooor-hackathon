// SPDX-License-Identifier: MIT
// Fixture: state-action-before-accrue — VULNERABLE
pragma solidity ^0.8.20;

contract CTokenVuln {
    uint256 public borrowIndex = 1e18;
    uint256 public exchangeRateStored = 1e18;
    uint256 public accrualBlockNumber;
    mapping(address => uint256) public accountBorrows;
    mapping(address => uint256) public balances;

    function interestRateModel() external pure returns (uint256) { return 0; }

    // VULN: redeem reads exchangeRateStored without calling accrueInterest first.
    function redeem(uint256 redeemTokens) external {
        uint256 amount = redeemTokens * exchangeRateStored / 1e18;
        balances[msg.sender] -= redeemTokens;
        (bool ok, ) = msg.sender.call{value: amount}(""); require(ok, "xfer");
    }

    // VULN: borrow snapshots stale borrowIndex.
    function borrow(uint256 amount) external {
        accountBorrows[msg.sender] += amount;
    }

    // VULN: repay against stale index.
    function repayBorrow(uint256 amount) external {
        accountBorrows[msg.sender] -= amount;
    }
}
