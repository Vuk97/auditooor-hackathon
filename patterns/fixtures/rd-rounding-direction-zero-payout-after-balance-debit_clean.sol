// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRdTokenClean {
    function transfer(address to, uint256 amount) external returns (bool);
}

library RdMath {
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return a == 0 ? 0 : (a - 1) / b + 1;
    }
}

contract RdRoundingDirectionZeroPayoutAfterBalanceDebitClean {
    using RdMath for uint256;

    IRdTokenClean public immutable usdc;
    mapping(address => uint256) public shares18;

    constructor(IRdTokenClean _usdc) {
        usdc = _usdc;
    }

    function withdraw(uint256 amount18) external {
        require(shares18[msg.sender] >= amount18, "insufficient");

        uint256 payout6 = amount18.ceilDiv(1e12);
        require(payout6 > 0, "zero payout");

        shares18[msg.sender] -= amount18;
        usdc.transfer(msg.sender, payout6);
    }
}
