// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LockClean {
    struct Lock { uint256 amount; uint256 end; }
    mapping(address => Lock) public locks;

    function depositFor(address user, uint256 amount, uint256 unlockTime) external {
        require(msg.sender == user || amount > 0, "zero-amount grief");
        Lock storage l = locks[user];
        l.amount += amount;
        if (unlockTime > l.end && msg.sender == user) {
            l.end = unlockTime;
        }
    }
}
