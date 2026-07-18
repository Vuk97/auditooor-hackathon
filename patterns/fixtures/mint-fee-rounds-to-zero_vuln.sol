// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MintFeeRoundsToZeroVuln {
    uint256 public feeBps = 30; // 0.30%
    mapping(address => uint256) public balances;
    uint256 public collectedFees;

    // VULN: amount * feeBps / 10000 rounds down. For amount = 333 with
    // feeBps = 30 the fee is 0 (333 * 30 = 9990, 9990 / 10000 = 0). A user
    // loops mint() with tiny amounts to mint fee-free.
    function mint(uint256 amount) external {
        uint256 fee = amount * feeBps / 10000;
        collectedFees += fee;
        balances[msg.sender] += amount - fee;
    }

    // VULN: same bug, different surface.
    function swap(uint256 amountIn) external returns (uint256 out) {
        uint256 fee = amountIn * feeBps / 10000;
        collectedFees += fee;
        out = amountIn - fee;
    }
}
