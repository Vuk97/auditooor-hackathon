// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DonateReservePositive {
    mapping(address => uint256) public collateralBalances;
    uint256 public reserves;

    function donateToReserves(uint256 amount) external {
        require(amount > 0, "amount=0");
        collateralBalances[msg.sender] -= amount;
        reserves += amount;
        // Missing post-state solvency guard.
    }
}
