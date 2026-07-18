// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegateClean {
    uint256 public constant MAX_DELEGATES = 16;
    mapping(address => address[]) public delegatees;
    mapping(address => uint256) public power;

    // Detector MUST NOT fire: hard small cap (<= 16) is enforced before append.
    function delegate(address to, uint256 amount) external {
        address[] storage arr = delegatees[msg.sender];
        require(arr.length <= 16, "too many delegates");
        for (uint256 i = 0; i < arr.length; i++) {
            power[arr[i]] -= 1;
        }
        arr.push(to);
        power[to] += 1;
    }
}
