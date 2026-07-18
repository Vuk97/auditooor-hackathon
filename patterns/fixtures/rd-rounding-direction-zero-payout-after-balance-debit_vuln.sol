// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRdToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RdRoundingDirectionZeroPayoutAfterBalanceDebitPositive {
    IRdToken public immutable usdc;
    mapping(address => uint256) public shares18;

    constructor(IRdToken _usdc) {
        usdc = _usdc;
    }

    function withdraw(uint256 amount18) external {
        require(shares18[msg.sender] >= amount18, "insufficient");
        shares18[msg.sender] -= amount18;

        uint256 payout6 = amount18 / 1e12;
        usdc.transfer(msg.sender, payout6);
    }
}
