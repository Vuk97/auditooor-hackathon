// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CommunityTreasury {
    mapping(address => uint256) public memberPoints;
    uint256 public reservePool;

    // Matches function-name and subtraction shape, but contract has no
    // lending-account semantics; detector precondition should suppress.
    function donateToReserves(uint256 amount) external {
        require(amount > 0, "amount=0");
        memberPoints[msg.sender] -= amount;
        reservePool += amount;
    }
}
