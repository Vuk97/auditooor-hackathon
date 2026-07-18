// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ArrayVuln {
    address[] public participants;

    function join() external {
        participants.push(msg.sender);
    }
}
