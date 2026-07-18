// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LockVuln {
    struct Lock { uint256 amount; uint256 end; }
    mapping(address => Lock) public locks;

    /// VULN: anyone can extend `user`'s lock duration.
    function depositFor(address user, uint256 amount, uint256 unlockTime) external {
        Lock storage l = locks[user];
        l.amount += amount;
        l.end = unlockTime;
    }
}
