// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MintFeeRoundsToZeroClean {
    uint256 public feeBps = 30; // 0.30%
    mapping(address => uint256) public balances;
    uint256 public collectedFees;

    // FIX: round fee UP so even 1-wei mints pay at least 1 wei of fee.
    // (amount * feeBps + 9999) / 10000 is the standard ceil-div form.
    function mint(uint256 amount) external {
        uint256 fee = (amount * feeBps + 9999) / 10000;
        collectedFees += fee;
        balances[msg.sender] += amount - fee;
    }

    // FIX: same ceiling-round approach for swap.
    function swap(uint256 amountIn) external returns (uint256 out) {
        uint256 fee = (amountIn * feeBps + 9999) / 10000;
        collectedFees += fee;
        out = amountIn - fee;
    }
}
