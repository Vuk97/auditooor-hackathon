// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeVuln {
    uint256 public constant MAX_FEE = 1000; // 10%
    uint256 public fee;
    address public owner;

    /// VULN: constructor bypasses MAX_FEE cap that setFee enforces.
    constructor(uint256 _fee) {
        fee = _fee;
        owner = msg.sender;
    }

    function setFee(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        require(_fee <= MAX_FEE, "fee too high");
        fee = _fee;
    }
}
