// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LendingClean {
    mapping(address => uint256) public debt;
    uint256 public rate = 1e15;
    uint256 public constant SCALE = 1e18;
    uint256 public constant MIN_DEBT = 100e18;

    function borrow(uint256 amount) external {
        require(amount + debt[msg.sender] >= MIN_DEBT, "dust");
        // Round up: mulDivUp
        uint256 interest = (debt[msg.sender] * rate + SCALE - 1) / SCALE;
        debt[msg.sender] += amount + interest;
    }
}
