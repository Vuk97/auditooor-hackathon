// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ArrayClean {
    address[] public participants;

    function join() external {
        participants.push(msg.sender);
    }

    function leave(uint256 idx) external {
        require(participants[idx] == msg.sender, "not you");
        participants[idx] = participants[participants.length - 1];
        participants.pop();
    }
}
