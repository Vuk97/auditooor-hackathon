// SPDX-License-Identifier: MIT
// Fixture: state-action-before-accrue — CLEAN
pragma solidity ^0.8.20;

contract CTokenClean {
    uint256 public borrowIndex = 1e18;
    uint256 public exchangeRateStored = 1e18;
    uint256 public accrualBlockNumber;
    mapping(address => uint256) public accountBorrows;
    mapping(address => uint256) public balances;

    function interestRateModel() external pure returns (uint256) { return 0; }

    function accrueInterest() public {
        accrualBlockNumber = block.number;
    }

    // CLEAN: accrueInterest called first.
    function redeem(uint256 redeemTokens) external {
        accrueInterest();
        uint256 amount = redeemTokens * exchangeRateStored / 1e18;
        balances[msg.sender] -= redeemTokens;
        (bool ok, ) = msg.sender.call{value: amount}(""); require(ok, "xfer");
    }

    function borrow(uint256 amount) external {
        accrueInterest();
        accountBorrows[msg.sender] += amount;
    }

    function repayBorrow(uint256 amount) external {
        accrueInterest();
        accountBorrows[msg.sender] -= amount;
    }
}
