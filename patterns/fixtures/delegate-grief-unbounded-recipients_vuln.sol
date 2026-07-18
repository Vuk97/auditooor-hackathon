// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegateVuln {
    uint256 public constant MAX_DELEGATES = 1024;
    mapping(address => address[]) public delegatees;
    mapping(address => uint256) public power;

    // Detector MUST fire: loops over delegatees[from] with no small cap check.
    function delegate(address to, uint256 amount) external {
        address[] storage arr = delegatees[msg.sender];
        for (uint256 i = 0; i < arr.length; i++) {
            power[arr[i]] -= 1;
        }
        arr.push(to);
        power[to] += 1;
    }
}
