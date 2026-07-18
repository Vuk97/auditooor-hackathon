// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RefundVuln {
    uint256 public liquidity = 4 ether;
    mapping(address => uint256) public tokenOut;

    // VULN: on partial fill, refunds full msg.value instead of msg.value - spent
    function swap() external payable {
        uint256 spent = msg.value < liquidity ? msg.value : liquidity;
        tokenOut[msg.sender] += spent;
        liquidity -= spent;
        if (spent < msg.value) {
            (bool ok, ) = msg.sender.call{value: msg.value}("");
            require(ok, "refund");
        }
    }
}
