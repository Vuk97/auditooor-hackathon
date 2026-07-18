// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RefundClean {
    uint256 public liquidity = 4 ether;
    mapping(address => uint256) public tokenOut;

    // CLEAN: refunds unused amount only
    function swap() external payable {
        uint256 spent = msg.value < liquidity ? msg.value : liquidity;
        tokenOut[msg.sender] += spent;
        liquidity -= spent;
        uint256 refund = msg.value - spent;
        if (refund > 0) {
            (bool ok, ) = msg.sender.call{value: refund}("");
            require(ok, "refund");
        }
    }
}
